#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <limits.h>
#include "relayd.h"

// Define the global interfaces list (used by main_for_fuzz.c and other modules)
struct list_head interfaces = LIST_HEAD_INIT(interfaces);
// Note: pending_routes is static in main.c, so we can't access it directly

int debug = 0;
uint8_t local_addr[4] = {192, 168, 1, 1};
int local_route_table = 0;

// these vars are in main.c: 
static int host_timeout = 30;
static int host_ping_tries = 5;
static int inet_sock = -1;
static int forward_bcast = 1;
static int forward_dhcp = 1;
static int parse_dhcp = 1;

static bool fuzz_initialized = false;
static bool mock_rif_in_list = false;

#define FUZZ_DEBUG(fmt, ...)

// Initialize mock_rif without static list initialization to avoid conflicts
static struct relayd_interface mock_rif = {
    .ifname = "eth0",
    .sll = {
        .sll_family = AF_PACKET,
        .sll_protocol = 0,
        .sll_ifindex = 1,
        .sll_hatype = ARPHRD_ETHER,
        .sll_pkttype = PACKET_BROADCAST,
        .sll_halen = ETH_ALEN,
        .sll_addr = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    },
    .src_ip = {192, 168, 1, 100},
    .managed = false,
    .rt_table = 100,
    // Don't initialize list heads statically - will be done at runtime
};

static void cleanup_fuzzing_state(void) {
    struct relayd_host *host, *host_tmp;
    
    // Only clean up if hosts list is initialized and safe to traverse
    if (mock_rif.hosts.next && mock_rif.hosts.prev && 
        mock_rif.hosts.next != &mock_rif.hosts && 
        !list_empty(&mock_rif.hosts)) {
        
        list_for_each_entry_safe(host, host_tmp, &mock_rif.hosts, list) {
            if (!host) continue; // Safety check
            
            // Free any routes first  
            struct relayd_route *route, *route_tmp;
            if (host->routes.next && host->routes.prev && 
                host->routes.next != &host->routes && 
                !list_empty(&host->routes)) {
                
                list_for_each_entry_safe(route, route_tmp, &host->routes, list) {
                    if (route) {
                        list_del(&route->list);
                        free(route);
                    }
                }
            }
            
            // Remove from list and free memory
            list_del(&host->list);
            free(host);
        }
    }
    
    // Remove mock_rif from interfaces list if it was added safely
    if (mock_rif_in_list && 
        mock_rif.list.next && mock_rif.list.prev && 
        mock_rif.list.next != &mock_rif.list) {
        list_del(&mock_rif.list);
        mock_rif_in_list = false;
    }
    
    // Close socket if open
    if (inet_sock >= 0) {
        close(inet_sock);
        inet_sock = -1;
    }
    
    // Properly reinitialize lists - always safe to do
    INIT_LIST_HEAD(&mock_rif.hosts);
    INIT_LIST_HEAD(&mock_rif.list);
    INIT_LIST_HEAD(&interfaces);
    
    // Reset flags
    mock_rif_in_list = false;
    
    // Note: Can't clean pending_routes as it's static in main.c
    // This is acceptable for fuzzing purposes
}

static void init_fuzzing_environment(void) {
    // Always clean up previous state first
    cleanup_fuzzing_state();
    
    // Initialize fresh state
    INIT_LIST_HEAD(&interfaces);
    INIT_LIST_HEAD(&mock_rif.list);
    INIT_LIST_HEAD(&mock_rif.hosts);
    
    if (inet_sock < 0) {
        inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (inet_sock < 0) {
            inet_sock = -1;
        }
    }
    
    debug = 1;
    mock_rif_in_list = false;
    fuzz_initialized = true;
}

static void fuzz_dhcp_packet(const uint8_t *data, size_t size) {
    // DHCP packet needs: Ethernet(14) + IP(20) + UDP(8) + DHCP(240+) = minimum ~282 bytes
    // But we want to test truncated packets too, so use smaller minimum
    if (size < 10) {
        return;
    }
    
    // Test both directions and parsing modes
    relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, true, true);
    relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, false, true);
    relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, true, false);
    relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, false, false);
    
    // Test with larger size to trigger different validation paths
    if (size >= 50) {
        relayd_handle_dhcp_packet(&mock_rif, (void *)data, size + 1000, true, true);
    }
}

static void fuzz_broadcast_packet(const uint8_t *data, size_t size) {
    // Ethernet header is 14 bytes minimum, but we want to test edge cases
    if (size < 6) {
        return;
    }
    
    // Test with raw data
    relayd_forward_bcast_packet(&mock_rif, (void *)data, size);
    
    // Test with crafted ethernet header if we have enough data
    if (size >= 14) {
        struct {
            struct ether_header eth;
            uint8_t payload[2048];
        } __packed pkt;
        
        // Create a basic ethernet frame structure
        memset(&pkt, 0, sizeof(pkt));
        pkt.eth.ether_type = htons(0x0800); // IP
        memcpy(pkt.eth.ether_dhost, "\xff\xff\xff\xff\xff\xff", 6); // broadcast
        memcpy(pkt.eth.ether_shost, mock_rif.sll.sll_addr, 6);
        
        size_t copy_size = (size - 14 > sizeof(pkt.payload)) ? sizeof(pkt.payload) : size - 14;
        memcpy(pkt.payload, data + 14, copy_size);
        
        relayd_forward_bcast_packet(&mock_rif, &pkt, 14 + copy_size);
    }
}

static void fuzz_host_refresh(const uint8_t *data, size_t size) {
    if (size < 10) {
        return;
    }
    
    const uint8_t *mac_addr = data;
    const uint8_t *ip_addr = data + 6;
    
    struct relayd_host *host = relayd_refresh_host(&mock_rif, mac_addr, ip_addr);
    
    if (host && size >= 15) {
        const uint8_t *dest_addr = data + 10;
        uint8_t mask = data[14] & 0x1F; // Limit to valid CIDR range (0-31)
        
        relayd_add_host_route(host, dest_addr, mask);
        
        // Test multiple routes on same host
        if (size >= 20) {
            const uint8_t *dest_addr2 = data + 15;
            uint8_t mask2 = (data[19] & 0x1F);
            relayd_add_host_route(host, dest_addr2, mask2);
        }
    }
    
    // Test refresh with same IP but different MAC (host movement)
    if (size >= 16) {
        uint8_t alt_mac[6];
        memcpy(alt_mac, data + 10, 6);
        alt_mac[5] ^= 0x01; // Slightly different MAC
        relayd_refresh_host(&mock_rif, alt_mac, ip_addr);
    }
}

static void fuzz_pending_route(const uint8_t *data, size_t size) {
    if (size < 9) {
        return;
    }
    
    const uint8_t *gateway = data;
    const uint8_t *dest = data + 4;
    uint8_t mask = data[8] & 0x1F; // Limit to valid CIDR range (0-31)
    int timeout = (size > 9) ? ((data[9] % 10) * 1000) : 5000;
    
    relayd_add_pending_route(gateway, dest, mask, timeout);
    
    // Test edge cases
    if (size >= 18) {
        // Test with zero timeout
        relayd_add_pending_route(data + 9, data + 13, mask, 0);
        
        // Test with very high timeout
        relayd_add_pending_route(data + 9, data + 13, mask, 60000);
    }
}

static void fuzz_mixed_operations(const uint8_t *data, size_t size) {
    if (size < 20) {
        return;
    }
    
    // Create some hosts first
    for (int i = 0; i < 3 && (i * 10 + 10) <= size; i++) {
        const uint8_t *mac = data + i * 10;
        const uint8_t *ip = data + i * 10 + 6;
        relayd_refresh_host(&mock_rif, mac, ip);
    }
    
    // Then test routes and packets
    if (size >= 30) {
        fuzz_pending_route(data + 20, size - 20);
    }
    
    if (size >= 40) {
        fuzz_dhcp_packet(data + 30, size - 30);
    }
}

static void fuzz_edge_cases(const uint8_t *data, size_t size) {
    if (size < 4) {
        return;
    }
    
    // Test with NULL-like scenarios (using mock_rif ensures no actual NULL)
    
    // Test very small packets
    for (int i = 1; i <= 10 && i <= size; i++) {
        relayd_handle_dhcp_packet(&mock_rif, (void *)data, i, true, true);
        relayd_forward_bcast_packet(&mock_rif, (void *)data, i);
    }
    
    // Test alignment issues
    if (size >= 16) {
        // Test unaligned access
        relayd_handle_dhcp_packet(&mock_rif, (void *)(data + 1), size - 1, true, true);
        relayd_handle_dhcp_packet(&mock_rif, (void *)(data + 2), size - 2, true, true);
        relayd_handle_dhcp_packet(&mock_rif, (void *)(data + 3), size - 3, true, true);
    }
    
    // Test boundary conditions
    if (size >= 8) {
        uint8_t zero_ip[4] = {0, 0, 0, 0};
        uint8_t bcast_ip[4] = {255, 255, 255, 255};
        uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};
        uint8_t bcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        
        relayd_refresh_host(&mock_rif, zero_mac, zero_ip);
        relayd_refresh_host(&mock_rif, bcast_mac, bcast_ip);
        relayd_refresh_host(&mock_rif, data, zero_ip);
        relayd_refresh_host(&mock_rif, zero_mac, data);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    
    init_fuzzing_environment();
    
    // Add mock_rif to interfaces only if not already there
    if (!mock_rif_in_list) {
        list_add(&mock_rif.list, &interfaces);
        mock_rif_in_list = true;
    }
    
    uint8_t fuzz_type = data[0] % 6; // Increased to 6 for new fuzz types
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;
    
    switch (fuzz_type) {
        case 0:
            fuzz_dhcp_packet(fuzz_data, fuzz_size);
            break;
            
        case 1:
            fuzz_broadcast_packet(fuzz_data, fuzz_size);
            break;
            
        case 2:
            fuzz_host_refresh(fuzz_data, fuzz_size);
            break;
            
        case 3:
            fuzz_pending_route(fuzz_data, fuzz_size);
            break;
            
        case 4:
            fuzz_mixed_operations(fuzz_data, fuzz_size);
            break;
            
        case 5:
            fuzz_edge_cases(fuzz_data, fuzz_size);
            break;
    }
    
    // Always clean up state after each iteration to ensure determinism and prevent crashes
    cleanup_fuzzing_state();
    
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
//     while (__AFL_LOOP(10000000000000000)) {
//         len = __AFL_FUZZ_TESTCASE_LEN;
//         LLVMFuzzerTestOneInput(buf, (size_t)len);
//     }
    
//     return 0;
// }