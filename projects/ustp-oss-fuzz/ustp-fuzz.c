#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include "worker.h"
#include "mstp.h"
#include "bridge_track.h"
#include "packet.h"

int cfg_proto = 0;
int cfg_no_subnet = 0;

static pthread_t fuzzer_worker_thread;
static volatile bool fuzzer_shutdown = false;
static struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct list_head queue;
} fuzzer_worker_queue = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
};

struct fuzzer_worker_queued_event {
    struct list_head list;
    struct worker_event ev;
};

// Helper function to cleanup event queue
static void cleanup_event_queue(void) {
    struct fuzzer_worker_queued_event *ev_item, *tmp;
    pthread_mutex_lock(&fuzzer_worker_queue.mutex);
    list_for_each_entry_safe(ev_item, tmp, &fuzzer_worker_queue.queue, list) {
        list_del(&ev_item->list);
        free(ev_item);
    }
    pthread_mutex_unlock(&fuzzer_worker_queue.mutex);
}

static void init_fuzzer_worker_queue(void) {
    INIT_LIST_HEAD(&fuzzer_worker_queue.queue);
}

static struct worker_event *fuzzer_worker_next_event(void) {
    struct fuzzer_worker_queued_event *ev;
    // Use stack allocation instead of static to avoid concurrency issues
    struct worker_event *ev_data = malloc(sizeof(*ev_data));
    if (!ev_data) {
        // Return shutdown event on allocation failure
        static struct worker_event shutdown_ev = { .type = WORKER_EV_SHUTDOWN };
        return &shutdown_ev;
    }

    pthread_mutex_lock(&fuzzer_worker_queue.mutex);
    while (list_empty(&fuzzer_worker_queue.queue) && !fuzzer_shutdown) {
        pthread_cond_wait(&fuzzer_worker_queue.cond, &fuzzer_worker_queue.mutex);
    }

    if (fuzzer_shutdown && list_empty(&fuzzer_worker_queue.queue)) {
        pthread_mutex_unlock(&fuzzer_worker_queue.mutex);
        ev_data->type = WORKER_EV_SHUTDOWN;
        return ev_data;
    }

    ev = list_first_entry(&fuzzer_worker_queue.queue, struct fuzzer_worker_queued_event, list);
    list_del(&ev->list);
    pthread_mutex_unlock(&fuzzer_worker_queue.mutex);

    memcpy(ev_data, &ev->ev, sizeof(*ev_data));
    free(ev);

    return ev_data;
}

static bool fuzzer_worker_queue_event(struct worker_event *ev) {
    struct fuzzer_worker_queued_event *evc;

    evc = malloc(sizeof(*evc));
    if (!evc) return false;
    
    memcpy(&evc->ev, ev, sizeof(*ev));

    pthread_mutex_lock(&fuzzer_worker_queue.mutex);
    list_add_tail(&evc->list, &fuzzer_worker_queue.queue);
    pthread_mutex_unlock(&fuzzer_worker_queue.mutex);

    pthread_cond_signal(&fuzzer_worker_queue.cond);
    return true;
}

static void fuzzer_handle_worker_event(struct worker_event *ev) {
    int result;
    
    switch (ev->type) {
    case WORKER_EV_ONE_SECOND:
        bridge_one_second();
        break;
    case WORKER_EV_BRIDGE_EVENT:
        bridge_event_handler();
        break;
    case WORKER_EV_RECV_PACKET:
        packet_rcv();
        break;
    case WORKER_EV_BRIDGE_ADD:
        result = bridge_create(ev->bridge_idx, &ev->bridge_config);
        if (result != 0) {
            // Log error but continue fuzzing
        }
        break;
    case WORKER_EV_BRIDGE_REMOVE:
        bridge_delete(ev->bridge_idx);
        break;
    default:
        // Test invalid event types too
        break;
    }
}

static void *fuzzer_worker_thread_fn(void *arg) {
    struct worker_event *ev;
    int event_count = 0;
    const int max_events = 2000; // Increased from 1000 for deeper testing

    while (event_count < max_events) {
        ev = fuzzer_worker_next_event();
        if (!ev || ev->type == WORKER_EV_SHUTDOWN) {
            if (ev && ev->type == WORKER_EV_SHUTDOWN) {
                // Only free if it's our allocated memory, not the static shutdown event
                if (ev != &(struct worker_event){ .type = WORKER_EV_SHUTDOWN }) {
                    free(ev);
                }
            }
            break;
        }

        fuzzer_handle_worker_event(ev);
        free(ev); // Free the allocated event data
        event_count++;
    }

    return NULL;
}

static bridge_t *create_mock_bridge(const uint8_t *data, size_t size) {
    if (size < 6) return NULL;
    
    bridge_t *br = calloc(1, sizeof(*br));
    if (!br) return NULL;

    memcpy(br->sysdeps.macaddr, data, 6);
    br->sysdeps.if_index = 1;
    strcpy(br->sysdeps.name, "br0");
    br->sysdeps.up = true;

    if (!MSTP_IN_bridge_create(br, br->sysdeps.macaddr)) {
        free(br);
        return NULL;
    }

    return br;
}

static void cleanup_mock_bridge(bridge_t *br) {
    if (br) {
        MSTP_IN_delete_bridge(br);
        free(br);
    }
}

static void fuzz_worker_thread(const uint8_t *data, size_t size) {
    if (size < 4) return;

    init_fuzzer_worker_queue();
    fuzzer_shutdown = false;

    if (pthread_create(&fuzzer_worker_thread, NULL, fuzzer_worker_thread_fn, NULL) != 0) {
        cleanup_event_queue();
        return;
    }

    size_t offset = 0;
    int event_count = 0;
    const int max_events = 200; // Increased from 50

    while (offset < size && event_count < max_events) {
        // Better size validation - check for minimum required bytes
        if (offset >= size) break;

        struct worker_event ev;
        memset(&ev, 0, sizeof(ev));

        // Allow testing invalid event types by not constraining to % 6
        ev.type = data[offset];
        offset++;

        if (offset + 4 <= size) {
            int32_t raw_bridge_idx;
            memcpy(&raw_bridge_idx, data + offset, 4);
            offset += 4;
            
            // Fix potential integer overflow with INT_MIN
            if (raw_bridge_idx == INT_MIN) {
                ev.bridge_idx = 1;
            } else {
                ev.bridge_idx = abs(raw_bridge_idx) % 1000 + 1;
            }
        } else {
            ev.bridge_idx = 1; // Default value
        }

        if (ev.type == WORKER_EV_BRIDGE_ADD && offset + 8 <= size) {
            CIST_BridgeConfig *cfg = &ev.bridge_config;
            memset(cfg, 0, sizeof(*cfg));
            
            // Test different protocol versions instead of hardcoding protoRSTP
            uint8_t proto_choice = data[offset] % 4;
            switch (proto_choice) {
                case 0: cfg->protocol_version = protoSTP; break;
                case 1: cfg->protocol_version = protoRSTP; break;
                case 2: cfg->protocol_version = protoMSTP; break;
                default: cfg->protocol_version = data[offset]; break; // Test invalid values
            }
            cfg->set_protocol_version = true;
            
            // Enhanced configuration with more parameters
            cfg->bridge_forward_delay = (data[offset + 1] % 30) + 4; // 4-33 seconds
            cfg->set_bridge_forward_delay = true;
            cfg->bridge_max_age = (data[offset + 2] % 35) + 6; // 6-40 seconds  
            cfg->set_bridge_max_age = true;
            cfg->bridge_hello_time = (data[offset + 3] % 10) + 1; // 1-10 seconds
            cfg->set_bridge_hello_time = true;
            
            // Add more configuration parameters
            if (offset + 8 <= size) {
                cfg->max_hops = data[offset + 4] % 21; // 0-20
                cfg->set_max_hops = true;
                cfg->tx_hold_count = data[offset + 5] % 10 + 1; // 1-10
                cfg->set_tx_hold_count = true;
            }
            
            offset += 6;
        }

        if (!fuzzer_worker_queue_event(&ev)) {
            // Failed to queue event, stop generating more
            break;
        }
        event_count++;
    }

    // Improved shutdown synchronization
    pthread_mutex_lock(&fuzzer_worker_queue.mutex);
    fuzzer_shutdown = true;
    pthread_cond_broadcast(&fuzzer_worker_queue.cond);
    pthread_mutex_unlock(&fuzzer_worker_queue.mutex);

    pthread_join(fuzzer_worker_thread, NULL);

    cleanup_event_queue();
}

static void fuzz_mstp_create_msti(const uint8_t *data, size_t size) {
    if (size < 8) return;

    bridge_t *br = create_mock_bridge(data, size);
    if (!br) return;

    size_t offset = 6;
    int test_count = 0;
    const int max_tests = 50; // Increased from 20

    while (offset + 2 <= size && test_count < max_tests) {
        uint16_t mstid;
        memcpy(&mstid, data + offset, 2);
        offset += 2;

        uint16_t test_cases[] = {
            mstid,                    // Direct fuzzer input
            mstid % (MAX_MSTID + 1),  // Constrained to valid range
            0,                        // Invalid (CIST)
            1,                        // Minimum valid
            MAX_MSTID,               // Maximum valid
            MAX_MSTID + 1,           // Invalid (too large)
            65535,                   // Maximum uint16_t
            mstid | 0x8000,          // Test with high bit set
            mstid & 0x0FFF,          // Test with masked value
        };

        for (size_t i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]) && test_count < max_tests; i++) {
            uint16_t test_mstid = test_cases[i];
            
            bool result = MSTP_IN_create_msti(br, test_mstid);
            // Test deletion of created instances
            if (result && test_mstid > 0 && test_mstid <= MAX_MSTID) {
                MSTP_IN_delete_msti(br, test_mstid);
            }
            
            test_count++;
        }
    }

    // Test creation and deletion patterns
    for (uint16_t i = 1; i <= 15 && i <= MAX_MSTID && test_count < max_tests; i++) {
        if (MSTP_IN_create_msti(br, i)) {
            // Test immediate deletion
            MSTP_IN_delete_msti(br, i);
        }
        test_count++;
    }

    // Test duplicate creation
    if (test_count < max_tests) {
        MSTP_IN_create_msti(br, 1);
        MSTP_IN_create_msti(br, 1); // Should handle duplicate gracefully
        MSTP_IN_delete_msti(br, 1);
        test_count += 3;
    }

    cleanup_mock_bridge(br);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Expand choices to test more combinations
    uint8_t fuzzer_choice = data[0] % 4;
    
    switch (fuzzer_choice) {
        case 0:
            fuzz_worker_thread(data + 1, size - 1);
            break;
        case 1:
            fuzz_mstp_create_msti(data + 1, size - 1);
            break;
        case 2:
            if (size >= 20) {
                size_t split = size / 2;
                fuzz_worker_thread(data + 1, split - 1);
                fuzz_mstp_create_msti(data + split, size - split);
            }
            break;
        case 3:
            // New: Test sequential worker then msti operations
            if (size >= 10) {
                size_t third = size / 3;
                fuzz_worker_thread(data + 1, third);
                fuzz_mstp_create_msti(data + 1 + third, third);
                fuzz_worker_thread(data + 1 + 2 * third, size - 1 - 2 * third);
            }
            break;
    }

    return 0;
}



// #ifndef __AFL_FUZZ_TESTCASE_LEN

// ssize_t fuzz_len;
// unsigned char fuzz_buf[1024000];

// #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
// #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf  
// #define __AFL_FUZZ_INIT() void sync(void);
// #define __AFL_LOOP(x) \
//     ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
// #define __AFL_INIT() sync()

// #endif

// __AFL_FUZZ_INIT();

// #pragma clang optimize off
// #pragma GCC optimize("O0")

// int main(int argc, char **argv)
// {
//     (void)argc; (void)argv; 
    
//     ssize_t len;
//     unsigned char *buf;

//     __AFL_INIT();
//     buf = __AFL_FUZZ_TESTCASE_BUF;
//     while (__AFL_LOOP(INT_MAX)) {
//         len = __AFL_FUZZ_TESTCASE_LEN;
//         LLVMFuzzerTestOneInput(buf, (size_t)len);
//     }
    
//     return 0;
// }
