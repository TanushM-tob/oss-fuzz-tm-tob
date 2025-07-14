#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "worker.h"
#include "mstp.h"
#include "bridge_track.h"

int cfg_proto = 0;
int cfg_no_subnet = 0;

static pthread_t fuzzer_worker_thread;
static bool fuzzer_shutdown = false;
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

static void init_fuzzer_worker_queue(void) {
    INIT_LIST_HEAD(&fuzzer_worker_queue.queue);
}

static struct worker_event *fuzzer_worker_next_event(void) {
    struct fuzzer_worker_queued_event *ev;
    static struct worker_event ev_data;

    pthread_mutex_lock(&fuzzer_worker_queue.mutex);
    while (list_empty(&fuzzer_worker_queue.queue) && !fuzzer_shutdown) {
        pthread_cond_wait(&fuzzer_worker_queue.cond, &fuzzer_worker_queue.mutex);
    }

    if (fuzzer_shutdown && list_empty(&fuzzer_worker_queue.queue)) {
        pthread_mutex_unlock(&fuzzer_worker_queue.mutex);
        ev_data.type = WORKER_EV_SHUTDOWN;
        return &ev_data;
    }

    ev = list_first_entry(&fuzzer_worker_queue.queue, struct fuzzer_worker_queued_event, list);
    list_del(&ev->list);
    pthread_mutex_unlock(&fuzzer_worker_queue.mutex);

    memcpy(&ev_data, &ev->ev, sizeof(ev_data));
    free(ev);

    return &ev_data;
}

static void fuzzer_worker_queue_event(struct worker_event *ev) {
    struct fuzzer_worker_queued_event *evc;

    evc = malloc(sizeof(*evc));
    if (!evc) return;
    
    memcpy(&evc->ev, ev, sizeof(*ev));

    pthread_mutex_lock(&fuzzer_worker_queue.mutex);
    list_add_tail(&evc->list, &fuzzer_worker_queue.queue);
    pthread_mutex_unlock(&fuzzer_worker_queue.mutex);

    pthread_cond_signal(&fuzzer_worker_queue.cond);
}

static void fuzzer_handle_worker_event(struct worker_event *ev) {
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
        bridge_create(ev->bridge_idx, &ev->bridge_config);
        break;
    case WORKER_EV_BRIDGE_REMOVE:
        bridge_delete(ev->bridge_idx);
        break;
    default:
        return;
    }
}

static void *fuzzer_worker_thread_fn(void *arg) {
    struct worker_event *ev;
    int event_count = 0;
    const int max_events = 1000;

    while (event_count < max_events) {
        ev = fuzzer_worker_next_event();
        if (ev->type == WORKER_EV_SHUTDOWN)
            break;

        fuzzer_handle_worker_event(ev);
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

static void fuzz_worker_thread(const uint8_t *data, size_t size) {
    if (size < 4) return;

    init_fuzzer_worker_queue();
    fuzzer_shutdown = false;

    if (pthread_create(&fuzzer_worker_thread, NULL, fuzzer_worker_thread_fn, NULL) != 0) {
        return;
    }

    size_t offset = 0;
    int event_count = 0;
    const int max_events = 50;

    while (offset < size && event_count < max_events) {
        if (offset + sizeof(struct worker_event) > size) break;

        struct worker_event ev;
        memset(&ev, 0, sizeof(ev));

        ev.type = data[offset] % 6;
        offset++;

        if (offset + 4 <= size) {
            memcpy(&ev.bridge_idx, data + offset, 4);
            offset += 4;
            
            ev.bridge_idx = abs(ev.bridge_idx) % 1000 + 1;
        }

        if (ev.type == WORKER_EV_BRIDGE_ADD && offset + 10 <= size) {
            CIST_BridgeConfig *cfg = &ev.bridge_config;
            memset(cfg, 0, sizeof(*cfg));
            
            cfg->protocol_version = protoRSTP;
            cfg->set_protocol_version = true;
            cfg->bridge_forward_delay = (data[offset] % 30) + 4; // 4-33 seconds
            cfg->set_bridge_forward_delay = true;
            cfg->bridge_max_age = (data[offset + 1] % 35) + 6; // 6-40 seconds  
            cfg->set_bridge_max_age = true;
            cfg->bridge_hello_time = (data[offset + 2] % 10) + 1; // 1-10 seconds
            cfg->set_bridge_hello_time = true;
            
            offset += 3;
        }

        fuzzer_worker_queue_event(&ev);
        event_count++;
    }

    fuzzer_shutdown = true;
    pthread_cond_signal(&fuzzer_worker_queue.cond);

    pthread_join(fuzzer_worker_thread, NULL);

    struct fuzzer_worker_queued_event *ev_item, *tmp;
    pthread_mutex_lock(&fuzzer_worker_queue.mutex);
    list_for_each_entry_safe(ev_item, tmp, &fuzzer_worker_queue.queue, list) {
        list_del(&ev_item->list);
        free(ev_item);
    }
    pthread_mutex_unlock(&fuzzer_worker_queue.mutex);
}

static void fuzz_mstp_create_msti(const uint8_t *data, size_t size) {
    if (size < 8) return;

    bridge_t *br = create_mock_bridge(data, size);
    if (!br) return;

    size_t offset = 6;
    int test_count = 0;
    const int max_tests = 20;

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
        };

        for (size_t i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]) && test_count < max_tests; i++) {
            uint16_t test_mstid = test_cases[i];
            
            bool result = MSTP_IN_create_msti(br, test_mstid);
            
            test_count++;
        }
    }

    for (uint16_t i = 1; i <= 10 && i <= MAX_MSTID && test_count < max_tests; i++) {
        MSTP_IN_create_msti(br, i);
        test_count++;
    }

    if (test_count < max_tests) {
        MSTP_IN_create_msti(br, 1);
        MSTP_IN_create_msti(br, 1);
        test_count += 2;
    }

    MSTP_IN_delete_bridge(br);
    free(br);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    uint8_t fuzzer_choice = data[0] % 3;
    
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
    }

    return 0;
}