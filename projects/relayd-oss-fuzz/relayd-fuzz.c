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

#include "relayd.h"

struct list_head interfaces = { &interfaces, &interfaces };
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

#define FUZZ_DEBUG(fmt, ...)

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
};

static void init_fuzzing_environment(void) {
    if (fuzz_initialized) {
        return;
    }
    
    if (interfaces.next == NULL || interfaces.prev == NULL) {
        INIT_LIST_HEAD(&interfaces);
    }
    
    INIT_LIST_HEAD(&mock_rif.list);
    INIT_LIST_HEAD(&mock_rif.hosts);
    
    if (inet_sock < 0) {
        inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (inet_sock < 0) {
            inet_sock = -1;
        }
    }
    
    debug = 1;
    
    fuzz_initialized = true;
}

static void fuzz_dhcp_packet(const uint8_t *data, size_t size) {
    if (size < 20) {
        return;
    }
    
    relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, true, true);
    relayd_handle_dhcp_packet(&mock_rif, (void *)data, size, false, true);
}

static void fuzz_broadcast_packet(const uint8_t *data, size_t size) {
    if (size < 14) {
        return;
    }
    
    relayd_forward_bcast_packet(&mock_rif, (void *)data, size);
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
        uint8_t mask = data[14];
        
        relayd_add_host_route(host, dest_addr, mask);
    }
}

static void fuzz_pending_route(const uint8_t *data, size_t size) {
    if (size < 9) {
        return;
    }
    
    const uint8_t *gateway = data;
    const uint8_t *dest = data + 4;
    uint8_t mask = data[8];
    int timeout = (size > 9) ? ((data[9] % 10) * 1000) : 5000;
    
    relayd_add_pending_route(gateway, dest, mask, timeout);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    
    init_fuzzing_environment();
    
    if (list_empty(&interfaces)) {
        list_add(&mock_rif.list, &interfaces);
    }
    
    uint8_t fuzz_type = data[0] % 4;
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
    }
    
    return 0;
}