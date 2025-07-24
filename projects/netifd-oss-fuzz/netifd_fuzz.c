#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include "netifd.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"
#include "config.h"
#include "device.h"
#include "system.h"

#include <uci.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blob.h>

// External functions we need to fuzz
extern void config_parse_interface(struct uci_section *s, bool alias);
extern void config_parse_route(struct uci_section *s, bool v6);
extern void interface_ip_add_route(struct interface *iface, struct blob_attr *attr, bool v6);

// Global fuzzing state
static bool g_fuzzing_initialized = false;
static struct uci_context *fuzz_uci_ctx = NULL;
static struct uci_package *fuzz_uci_pkg = NULL;

// Initialize minimal netifd environment for fuzzing
static void init_fuzzing_environment(void) {
    if (g_fuzzing_initialized) return;
    
    // Initialize interfaces list
    extern struct vlist_tree interfaces;
    extern void interface_update(struct vlist_tree *tree, struct vlist_node *node_new, struct vlist_node *node_old);
    vlist_init(&interfaces, avl_strcmp, interface_update);
    interfaces.keep_old = true;
    interfaces.no_delete = true;
    
    // Initialize minimal ubus context
    extern struct ubus_context *ubus_ctx;
    if (!ubus_ctx) {
        ubus_ctx = calloc(1, sizeof(struct ubus_context));
        if (ubus_ctx) {
            ubus_ctx->sock.fd = -1;
            INIT_LIST_HEAD(&ubus_ctx->pending);
            INIT_LIST_HEAD(&ubus_ctx->requests);
        }
    }
    
    g_fuzzing_initialized = true;
}

// Create a UCI section from fuzz data  
static struct uci_section *create_uci_section_from_fuzz(const uint8_t *data, size_t size, const char *type, const char *name) {
    if (size < 4) return NULL;
    
    // Create UCI context if needed
    if (!fuzz_uci_ctx) {
        fuzz_uci_ctx = uci_alloc_context();
        if (!fuzz_uci_ctx) return NULL;
    }
    
    // Create package if needed
    if (!fuzz_uci_pkg) {
        fuzz_uci_pkg = calloc(1, sizeof(struct uci_package));
        if (!fuzz_uci_pkg) return NULL;
        fuzz_uci_pkg->ctx = fuzz_uci_ctx;
        fuzz_uci_pkg->e.name = strdup("network");
        INIT_LIST_HEAD(&fuzz_uci_pkg->sections);
    }
    
    struct uci_section *section = NULL;
    int ret = uci_add_section(fuzz_uci_ctx, fuzz_uci_pkg, type, &section);
    if (ret != UCI_OK || !section) return NULL;
    
    // Set section name if provided
    if (name) {
        if (section->e.name) free((void*)section->e.name);
        section->e.name = strdup(name);
    }
    
    // Add some fuzzed options based on input data
    size_t offset = 0;
    while (offset + 4 < size) {
        uint8_t option_type = data[offset] % 10;
        offset++;
        
        const char *option_name = NULL;
        const char *option_value = NULL;
        
        switch (option_type) {
            case 0:
                option_name = "proto";
                option_value = (data[offset] % 2) ? "static" : "dhcp";
                break;
            case 1:
                option_name = "ipaddr";
                option_value = "192.168.1.1";
                break;
            case 2:
                option_name = "netmask";
                option_value = "255.255.255.0";
                break;
            case 3:
                option_name = "gateway";
                option_value = "192.168.1.254";
                break;
            case 4:
                option_name = "dns";
                option_value = "8.8.8.8";
                break;
            case 5:
                option_name = "metric";
                option_value = (data[offset] % 2) ? "100" : "200";
                break;
            case 6:
                option_name = "interface";
                option_value = "lan";
                break;
            case 7:
                option_name = "target";
                option_value = "0.0.0.0/0";
                break;
            case 8:
                option_name = "type";
                option_value = "bridge";
                break;
            case 9:
                option_name = "ports";
                option_value = "eth0 eth1";
                break;
        }
        
        if (option_name && option_value) {
            struct uci_ptr ptr = {
                .p = fuzz_uci_pkg,
                .s = section,
                .option = option_name,
                .value = option_value,
            };
            uci_set(fuzz_uci_ctx, &ptr);
        }
        
        offset++;
        if (offset >= size) break;
    }
    
    return section;
}

// Create a blob attribute from fuzz data for testing blob parsing
static struct blob_attr *create_blob_from_fuzz(const uint8_t *data, size_t size) {
    if (size < 8) return NULL;
    
    static struct blob_buf buf;
    static bool buf_initialized = false;
    
    if (buf_initialized) {
        blob_buf_free(&buf);
    }
    blob_buf_init(&buf, 0);
    buf_initialized = true;
    
    size_t offset = 0;
    
    // Add various blob fields based on fuzz data
    while (offset + 4 < size) {
        uint8_t field_type = data[offset] % 8;
        offset++;
        
        switch (field_type) {
            case 0: // String field
                if (offset + 4 <= size) {
                    uint32_t str_selector = data[offset] % 10;
                    const char *strings[] = {
                        "192.168.1.1", "eth0", "lan", "dhcp", "static",
                        "bridge", "8.8.8.8", "255.255.255.0", "0.0.0.0", "wan"
                    };
                    blobmsg_add_string(&buf, "value", strings[str_selector]);
                    offset += 4;
                }
                break;
                
            case 1: // Integer field
                if (offset + 4 <= size) {
                    uint32_t val;
                    memcpy(&val, data + offset, 4);
                    blobmsg_add_u32(&buf, "metric", val % 1000);
                    offset += 4;
                }
                break;
                
            case 2: // IP address
                blobmsg_add_string(&buf, "ipaddr", "192.168.1.1");
                break;
                
            case 3: // Gateway
                blobmsg_add_string(&buf, "gateway", "192.168.1.254");
                break;
                
            case 4: // Interface
                blobmsg_add_string(&buf, "interface", "lan");
                break;
                
            case 5: // Route target
                blobmsg_add_string(&buf, "target", "0.0.0.0/0");
                break;
                
            case 6: // Boolean
                blobmsg_add_u8(&buf, "enabled", data[offset] & 1);
                offset++;
                break;
                
            case 7: // Array of strings
                {
                    void *array = blobmsg_open_array(&buf, "list");
                    blobmsg_add_string(&buf, NULL, "eth0");
                    blobmsg_add_string(&buf, NULL, "eth1");
                    blobmsg_close_array(&buf, array);
                }
                break;
        }
        
        if (offset >= size) break;
    }
    
    return blob_data(buf.head);
}

// Fuzz UCI configuration parsing
static void fuzz_uci_config_parsing(const uint8_t *data, size_t size) {
    if (size < 8) return;
    
    uint8_t config_type = data[0] % 4;
    const uint8_t *config_data = data + 1;
    size_t config_size = size - 1;
    
    struct uci_section *section = NULL;
    
    switch (config_type) {
        case 0: // Interface config
            section = create_uci_section_from_fuzz(config_data, config_size, "interface", "lan");
            if (section) {
                bool alias = (config_data[0] % 2) == 1;
                config_parse_interface(section, alias);
            }
            break;
            
        case 1: // Route config
            section = create_uci_section_from_fuzz(config_data, config_size, "route", "default");
            if (section) {
                bool v6 = (config_data[0] % 2) == 1;
                config_parse_route(section, v6);
            }
            break;
            
                 case 2: // Second interface config (alternative to case 0)
             section = create_uci_section_from_fuzz(config_data, config_size, "interface", "wan");
             if (section) {
                 bool alias = (config_data[0] % 2) == 1;
                 config_parse_interface(section, alias);
             }
             break;
            
        case 3: // Interface route addition via blob
            {
                struct blob_attr *attr = create_blob_from_fuzz(config_data, config_size);
                if (attr) {
                    // Create a minimal interface for testing
                    struct interface *iface = calloc(1, sizeof(struct interface));
                    if (iface) {
                        iface->name = strdup("test_iface");
                        INIT_LIST_HEAD(&iface->errors);
                        
                        // Initialize interface IP structure
                        extern void interface_ip_init(struct interface *iface);
                        interface_ip_init(iface);
                        
                        bool v6 = (config_data[0] % 2) == 1;
                        interface_ip_add_route(iface, attr, v6);
                        
                        // Cleanup
                        if (iface->name) free((void*)iface->name);
                        free(iface);
                    }
                }
            }
            break;
    }
    
         // Note: UCI manages memory internally, we don't need to manually free sections/options
     // when they're created through uci_add_section/uci_set. They'll be freed when
     // the package/context is freed in the destructor.
}

// Simple blob message parsing fuzzer
static void fuzz_blob_parsing(const uint8_t *data, size_t size) {
    if (size < 16) return;
    
    // Try to parse the raw fuzz data as a blob message
    struct blob_attr *attr = (struct blob_attr *)data;
    
    // Basic sanity check on blob header
    if (blob_len(attr) > size - sizeof(struct blob_attr)) return;
    if (blob_len(attr) == 0) return;
    
    // Try to parse it as a blobmsg
    if (blobmsg_check_attr(attr, false)) {
        // Parse as different message types
        uint8_t parse_type = data[size-1] % 3;
        
        switch (parse_type) {
            case 0: // Parse as route config
                {
                    bool v6 = (data[size-2] % 2) == 1;
                    // Create a minimal interface
                    struct interface *iface = calloc(1, sizeof(struct interface));
                    if (iface) {
                        iface->name = strdup("blob_test");
                        INIT_LIST_HEAD(&iface->errors);
                        extern void interface_ip_init(struct interface *iface);
                        interface_ip_init(iface);
                        
                        interface_ip_add_route(iface, attr, v6);
                        
                        if (iface->name) free((void*)iface->name);
                        free(iface);
                    }
                }
                break;
                
            case 1: // Parse as JSON and convert back
                {
                    char *json_str = blobmsg_format_json(attr, true);
                    if (json_str) {
                        // Try to parse it back
                        static struct blob_buf parse_buf;
                        blob_buf_init(&parse_buf, 0);
                        blobmsg_add_json_from_string(&parse_buf, json_str);
                        blob_buf_free(&parse_buf);
                        free(json_str);
                    }
                }
                break;
                
            case 2: // Just iterate through the blob
                {
                    struct blob_attr *cur;
                    int rem;
                    blobmsg_for_each_attr(cur, attr, rem) {
                        // Just access the data to trigger any parsing issues
                        if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING) {
                            blobmsg_get_string(cur);
                        } else if (blobmsg_type(cur) == BLOBMSG_TYPE_INT32) {
                            blobmsg_get_u32(cur);
                        }
                    }
                }
                break;
        }
    }
}

// Main fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_fuzzing_environment();
    
    if (size < 4) return 0;
    
    // Choose fuzzing strategy based on first byte
    uint8_t strategy = data[0] % 3;
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;
    
    switch (strategy) {
        case 0:
            fuzz_uci_config_parsing(fuzz_data, fuzz_size);
            break;
        case 1:
            fuzz_blob_parsing(fuzz_data, fuzz_size);
            break;
        case 2:
            // Mix both approaches
            if (fuzz_size > 8) {
                size_t split = fuzz_size / 2;
                fuzz_uci_config_parsing(fuzz_data, split);
                fuzz_blob_parsing(fuzz_data + split, fuzz_size - split);
            }
            break;
    }
    
    return 0;
}

// // AFL++ integration
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

// int main(int argc, char **argv) {
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
//}

// Cleanup on exit
__attribute__((destructor))
static void fuzz_cleanup(void) {
    if (fuzz_uci_ctx) {
        // UCI context cleanup will handle the package cleanup
        uci_free_context(fuzz_uci_ctx);
        fuzz_uci_ctx = NULL;
        fuzz_uci_pkg = NULL; // Will be freed by uci_free_context
    }
}