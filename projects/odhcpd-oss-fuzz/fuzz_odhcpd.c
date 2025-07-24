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
#include <syslog.h>
#include <time.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <libubus.h>
#include <limits.h>
#include "src/odhcpd.h"
#include "src/dhcpv6.h"

static int mock_send_reply(const void *buf, size_t len,
                          const struct sockaddr *dest, socklen_t dest_len,
                          void *opaque) {
    return len;
}

static void fuzz_dhcpv4(const uint8_t *data, size_t size) {
    uint8_t *copy = malloc(size);
    if (!copy) return;
    memcpy(copy, data, size);
    
    struct interface iface;
    memset(&iface, 0, sizeof(iface));
    
    iface.ifflags = 0;
    iface.ifindex = 1;
    iface.ifname = "test0";
    iface.name = "test0";
    
    iface.dhcpv4 = MODE_SERVER;
    
    inet_pton(AF_INET, "192.168.1.100", &iface.dhcpv4_start_ip);
    inet_pton(AF_INET, "192.168.1.200", &iface.dhcpv4_end_ip);
    inet_pton(AF_INET, "192.168.1.1", &iface.dhcpv4_local);
    inet_pton(AF_INET, "192.168.1.255", &iface.dhcpv4_bcast);
    inet_pton(AF_INET, "255.255.255.0", &iface.dhcpv4_mask);
    
    int dummy_fd = -1;  
    iface.dhcpv4_event.uloop.fd = dummy_fd;
    
    INIT_LIST_HEAD(&iface.dhcpv4_assignments);
    INIT_LIST_HEAD(&iface.dhcpv4_fr_ips);
    
    iface.dns_service = true;
    iface.dhcp_leasetime = 3600; 
    iface.dhcpv4_forcereconf = false;
    
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(68); 
    inet_pton(AF_INET, "192.168.1.50", &client_addr.sin_addr);
    
    dhcpv4_handle_msg(&client_addr, copy, size, &iface, NULL, 
                      mock_send_reply, &dummy_fd);

    // Clean up any DHCP assignments created during message handling to prevent memory leaks
    struct dhcp_assignment *a, *tmp;
    list_for_each_entry_safe(a, tmp, &iface.dhcpv4_assignments, head) {
        free_assignment(a);
    }

    if (size >= 4 && size <= 1024) {
        uint8_t *config_copy = malloc(size);
        if (config_copy) {
            memcpy(config_copy, data, size);
            config_parse_interface(config_copy, size, "test_iface", true);
            free(config_copy);
        }
    }
    
    free(copy);
}

static void fuzz_dhcpv6(const uint8_t *data, size_t size) {
    uint8_t *copy = malloc(size);
    if (!copy) return;
    memcpy(copy, data, size);
    
    struct interface iface_server;
    memset(&iface_server, 0, sizeof(iface_server));
    
    iface_server.ifflags = 0;
    iface_server.ifindex = 1;
    iface_server.ifname = "test0";
    iface_server.name = "test0";
    iface_server.inuse = true;
    iface_server.external = false;
    iface_server.master = false;
    iface_server.ignore = false;
    
    iface_server.dhcpv6 = MODE_SERVER;
    iface_server.dhcpv6_event.uloop.fd = 1;
    
    INIT_LIST_HEAD(&iface_server.ia_assignments);
    
    struct odhcpd_ipaddr mock_addr6[2];
    memset(mock_addr6, 0, sizeof(mock_addr6));
    
    inet_pton(AF_INET6, "fe80::1", &mock_addr6[0].addr.in6);
    mock_addr6[0].prefix = 64;
    mock_addr6[0].preferred_lt = UINT32_MAX;
    mock_addr6[0].valid_lt = UINT32_MAX;
    
    inet_pton(AF_INET6, "2001:db8::1", &mock_addr6[1].addr.in6);
    mock_addr6[1].prefix = 64;
    mock_addr6[1].preferred_lt = UINT32_MAX;
    mock_addr6[1].valid_lt = UINT32_MAX;
    
    iface_server.addr6 = mock_addr6;
    iface_server.addr6_len = 2;
    
    struct in6_addr dns_servers[2];
    inet_pton(AF_INET6, "2001:db8::53", &dns_servers[0]);
    inet_pton(AF_INET6, "2001:db8::54", &dns_servers[1]);
    iface_server.dns = dns_servers;
    iface_server.dns_cnt = 2;
    iface_server.dns_service = true;
    
    iface_server.dhcp_leasetime = 3600;
    iface_server.always_rewrite_dns = false;
    
    iface_server.dhcpv6_assignall = true;
    iface_server.dhcpv6_pd = true;
    iface_server.dhcpv6_na = true;
    iface_server.dhcpv6_hostid_len = 64;
    
    struct sockaddr_in6 source_addr;
    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.sin6_family = AF_INET6;
    source_addr.sin6_port = htons(DHCPV6_CLIENT_PORT);
    inet_pton(AF_INET6, "2001:db8::100", &source_addr.sin6_addr);
    
    struct in6_addr dest_addr;
    inet_pton(AF_INET6, "ff02::1:2", &dest_addr);
    
    handle_dhcpv6(&source_addr, copy, size, &iface_server, &dest_addr);
    
    if (size >= 8) {
        struct interface iface_relay;
        memcpy(&iface_relay, &iface_server, sizeof(iface_relay));
        
        iface_relay.dhcpv6 = MODE_RELAY;
        iface_relay.master = false;
        iface_relay.ifname = "test1";
        iface_relay.name = "test1";
        iface_relay.ifindex = 2;
        
        memcpy(copy, data, size);
        
        handle_dhcpv6(&source_addr, copy, size, &iface_relay, &dest_addr);
        
        iface_relay.master = true;
        memcpy(copy, data, size);
        handle_dhcpv6(&source_addr, copy, size, &iface_relay, &dest_addr);
    }
    
    if (size >= 2) {
        uint8_t original_type = copy[1];
        
        uint8_t msg_types[] = {
            DHCPV6_MSG_SOLICIT,
            DHCPV6_MSG_ADVERTISE,
            DHCPV6_MSG_REQUEST,
            DHCPV6_MSG_CONFIRM,
            DHCPV6_MSG_RENEW,
            DHCPV6_MSG_REBIND,
            DHCPV6_MSG_REPLY,
            DHCPV6_MSG_RELEASE,
            DHCPV6_MSG_DECLINE,
            DHCPV6_MSG_RECONFIGURE,
            DHCPV6_MSG_INFORMATION_REQUEST,
            DHCPV6_MSG_RELAY_FORW,
            DHCPV6_MSG_RELAY_REPL,
            DHCPV6_MSG_DHCPV4_QUERY,
            DHCPV6_MSG_DHCPV4_RESPONSE
        };
        
        for (size_t i = 0; i < sizeof(msg_types); i++) {
            copy[1] = msg_types[i];
            handle_dhcpv6(&source_addr, copy, size, &iface_server, &dest_addr);
        }
        
        copy[1] = original_type;
    }
    
    struct in6_addr unicast_dest;
    inet_pton(AF_INET6, "2001:db8::200", &unicast_dest);
    handle_dhcpv6(&source_addr, copy, size, &iface_server, &unicast_dest);
    
    if (size >= 8) {
        struct interface iface_no_dns;
        memcpy(&iface_no_dns, &iface_server, sizeof(iface_no_dns));
        iface_no_dns.dns = NULL;
        iface_no_dns.dns_cnt = 0;
        handle_dhcpv6(&source_addr, copy, size, &iface_no_dns, &dest_addr);
    }
    
    // Clean up any DHCPv6 assignments created during message handling to prevent memory leaks
    struct dhcp_assignment *a, *tmp;
    list_for_each_entry_safe(a, tmp, &iface_server.ia_assignments, head) {
        free_assignment(a);
    }
    
    free(copy);
}

static void fuzz_ubus_dump(const uint8_t *data, size_t size) {
    struct {
        uint32_t id_and_len;
        uint8_t data[0];
    } *mock_blob = (void*)data;
    
    if (size < sizeof(uint32_t)) return;
    
    struct ubus_request mock_req = {0};
    
    handle_dump(&mock_req, 0, (struct blob_attr*)mock_blob);
}

static void fuzz_icmpv6(const uint8_t *data, size_t size) {
    uint8_t *copy = malloc(size);
    if (!copy) return;
    memcpy(copy, data, size);
    
    struct interface iface_router;
    memset(&iface_router, 0, sizeof(iface_router));
    
    iface_router.ifflags = 0;
    iface_router.ifindex = 1;
    iface_router.ifname = "test0";
    iface_router.name = "test0";
    iface_router.inuse = true;
    iface_router.external = false;
    iface_router.master = false;
    iface_router.ignore = false;
    
    iface_router.ra = MODE_SERVER;
    iface_router.router_event.uloop.fd = 1;
    
    struct odhcpd_ipaddr mock_addr6[2];
    memset(mock_addr6, 0, sizeof(mock_addr6));
    
    inet_pton(AF_INET6, "fe80::1", &mock_addr6[0].addr.in6);
    mock_addr6[0].prefix = 64;
    mock_addr6[0].preferred_lt = UINT32_MAX;
    mock_addr6[0].valid_lt = UINT32_MAX;
    
    inet_pton(AF_INET6, "2001:db8::1", &mock_addr6[1].addr.in6);
    mock_addr6[1].prefix = 64;
    mock_addr6[1].preferred_lt = UINT32_MAX;
    mock_addr6[1].valid_lt = UINT32_MAX;
    
    iface_router.addr6 = mock_addr6;
    iface_router.addr6_len = 2;
    
    iface_router.ra_maxinterval = 600;
    iface_router.ra_mininterval = 200;
    iface_router.ra_lifetime = 1800;
    iface_router.ra_reachabletime = 0;
    iface_router.ra_retranstime = 0;
    iface_router.ra_hoplimit = 64;
    iface_router.default_router = 1;
    iface_router.route_preference = 0;
    
    struct sockaddr_in6 source_addr;
    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.sin6_family = AF_INET6;
    source_addr.sin6_port = 0;
    inet_pton(AF_INET6, "fe80::2", &source_addr.sin6_addr);
    
    struct in6_addr dest_addr;
    inet_pton(AF_INET6, "ff02::1", &dest_addr);
    
    handle_icmpv6(&source_addr, copy, size, &iface_router, &dest_addr);
    
    if (size >= 8) {
        struct interface iface_relay;
        memcpy(&iface_relay, &iface_router, sizeof(iface_relay));
        
        iface_relay.ra = MODE_RELAY;
        iface_relay.master = false;
        iface_relay.ifname = "test1";
        iface_relay.name = "test1";
        iface_relay.ifindex = 2;
        
        memcpy(copy, data, size);
        
        handle_icmpv6(&source_addr, copy, size, &iface_relay, &dest_addr);
        
        iface_relay.master = true;
        memcpy(copy, data, size);
        handle_icmpv6(&source_addr, copy, size, &iface_relay, &dest_addr);
    }
    
    free(copy);
}

static void fuzz_ndp_solicit(const uint8_t *data, size_t size) {
    uint8_t *copy = malloc(size);
    if (!copy) return;
    memcpy(copy, data, size);
    
    struct interface iface_ndp;
    memset(&iface_ndp, 0, sizeof(iface_ndp));
    
    iface_ndp.ifflags = 0;
    iface_ndp.ifindex = 1;
    iface_ndp.ifname = "test0";
    iface_ndp.name = "test0";
    iface_ndp.inuse = true;
    iface_ndp.external = false;
    iface_ndp.master = false;
    iface_ndp.ignore = false;
    
    iface_ndp.ndp = MODE_RELAY;
    iface_ndp.ndp_event.uloop.fd = 1;
    iface_ndp.ndp_ping_fd = 2;
    iface_ndp.learn_routes = 1;
    
    struct odhcpd_ipaddr mock_addr6[2];
    memset(mock_addr6, 0, sizeof(mock_addr6));
    
    inet_pton(AF_INET6, "fe80::1", &mock_addr6[0].addr.in6);
    mock_addr6[0].prefix = 64;
    mock_addr6[0].preferred_lt = UINT32_MAX;
    mock_addr6[0].valid_lt = UINT32_MAX;
    
    inet_pton(AF_INET6, "2001:db8::1", &mock_addr6[1].addr.in6);
    mock_addr6[1].prefix = 64;
    mock_addr6[1].preferred_lt = UINT32_MAX;
    mock_addr6[1].valid_lt = UINT32_MAX;
    
    iface_ndp.addr6 = mock_addr6;
    iface_ndp.addr6_len = 2;
    
    struct sockaddr_ll source_ll;
    memset(&source_ll, 0, sizeof(source_ll));
    source_ll.sll_family = AF_PACKET;
    source_ll.sll_protocol = htons(ETH_P_IPV6);
    source_ll.sll_ifindex = iface_ndp.ifindex;
    source_ll.sll_hatype = ARPHRD_ETHER;
    source_ll.sll_halen = 6;
    source_ll.sll_addr[0] = 0x00;
    source_ll.sll_addr[1] = 0x11;
    source_ll.sll_addr[2] = 0x22;
    source_ll.sll_addr[3] = 0x33;
    source_ll.sll_addr[4] = 0x44;
    source_ll.sll_addr[5] = 0x55;
    
    struct in6_addr dest_addr;
    inet_pton(AF_INET6, "ff02::1", &dest_addr);
    
    handle_solicit(&source_ll, copy, size, &iface_ndp, &dest_addr);
    
    if (size >= 8) {
        struct interface iface_external;
        memcpy(&iface_external, &iface_ndp, sizeof(iface_external));
        
        iface_external.external = true;
        iface_external.ifname = "test_ext";
        iface_external.name = "test_ext";
        iface_external.ifindex = 3;
        
        memcpy(copy, data, size);
        
        handle_solicit(&source_ll, copy, size, &iface_external, &dest_addr);
    }
    
    free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    uint8_t selector = data[0] % 5;
    const uint8_t *rdata = data + 1;
    size_t payload_size = size - 1;
    
    switch (selector) {
        case 0:
            fuzz_dhcpv4(rdata, payload_size);
            break;
        case 1:
            fuzz_dhcpv6(rdata, payload_size);
            break;
        case 2:
            fuzz_ubus_dump(rdata, payload_size);
            break;
        case 3:
            fuzz_icmpv6(rdata, payload_size);
            break;
        case 4:
            fuzz_ndp_solicit(rdata, payload_size);
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