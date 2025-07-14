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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/vlist.h>
#include "dns.h"
#include "cache.h"
#include "interface.h"
#include "util.h"
#include "service.h"

int cfg_proto = 0;
int cfg_no_subnet = 0;

enum {
    BROWSE_SERVICE,
    BROWSE_ARRAY,
    BROWSE_ADDRESS,
    BROWSE_MAX
};

static const struct blobmsg_policy browse_policy[] = {
    [BROWSE_SERVICE]    = { "service", BLOBMSG_TYPE_STRING },
    [BROWSE_ARRAY]      = { "array", BLOBMSG_TYPE_BOOL },
    [BROWSE_ADDRESS]    = { "address", BLOBMSG_TYPE_BOOL },
};

enum query_attr {
    QUERY_QUESTION,
    QUERY_IFACE,
    QUERY_TYPE,
    QUERY_MAX
};

static const struct blobmsg_policy query_policy[QUERY_MAX] = {
    [QUERY_QUESTION]= { "question", BLOBMSG_TYPE_STRING },
    [QUERY_IFACE]   = { "interface", BLOBMSG_TYPE_STRING },
    [QUERY_TYPE]    = { "type", BLOBMSG_TYPE_INT32 },
};

static struct blob_buf fuzz_b;

static int fuzz_umdns_browse(struct blob_attr *msg) {
    struct cache_service *s, *q;
    char *buffer = (char *) mdns_buf;
    struct blob_attr *data[BROWSE_MAX];
    void *c1 = NULL, *c2;
    char *service = NULL;
    int array = 0;
    bool address = true;

    if (!msg) return -1;

    blobmsg_parse(browse_policy, BROWSE_MAX, data, blob_data(msg), blob_len(msg));
    if (data[BROWSE_SERVICE])
        service = blobmsg_get_string(data[BROWSE_SERVICE]);
    if (data[BROWSE_ARRAY])
        array = blobmsg_get_u8(data[BROWSE_ARRAY]);
    if (data[BROWSE_ADDRESS])
        address = blobmsg_get_bool(data[BROWSE_ADDRESS]);

    blob_buf_init(&fuzz_b, 0);

    avl_for_each_element(&services, s, avl) {
        const char *hostname = buffer;
        char *local;

        snprintf(buffer, MAX_NAME_LEN, "%s", (const char *) s->avl.key);
        local = strstr(buffer, ".local");
        if (local)
            *local = '\0';
        if (!strcmp(buffer, "_tcp") || !strcmp(buffer, "_udp"))
            continue;
        if (service && strcmp(buffer, service))
            continue;
        if (!c1) {
            c1 = blobmsg_open_table(&fuzz_b, buffer);
        }
        snprintf(buffer, MAX_NAME_LEN, "%s", s->entry);
        local = strstr(buffer, "._");
        if (local)
            *local = '\0';
        c2 = blobmsg_open_table(&fuzz_b, buffer);
        strncat(buffer, ".local", MAX_NAME_LEN);
        if (s->iface)
            blobmsg_add_string(&fuzz_b, "iface", s->iface->name);
        cache_dump_records(&fuzz_b, s->entry, array, &hostname);
        if (address)
            cache_dump_records(&fuzz_b, hostname, array, NULL);
        blobmsg_close_table(&fuzz_b, c2);
        q = avl_next_element(s, avl);
        if (!q || avl_is_last(&services, &s->avl) || strcmp(s->avl.key, q->avl.key)) {
            blobmsg_close_table(&fuzz_b, c1);
            c1 = NULL;
        }
    }

    return 0;
}

static int fuzz_umdns_query(struct blob_attr *msg, const char *method) {
    struct interface *iface_v4 = NULL, *iface_v6 = NULL;
    struct blob_attr *tb[QUERY_MAX], *c;
    const char *question = C_DNS_SD;
    const char *ifname;
    int type = TYPE_ANY;

    if (!msg || !method) return -1;

    blobmsg_parse(query_policy, QUERY_MAX, tb, blob_data(msg), blob_len(msg));

    if ((c = tb[QUERY_QUESTION]))
        question = blobmsg_get_string(c);

    if ((c = tb[QUERY_TYPE]))
        type = blobmsg_get_u32(c);

    if ((c = tb[QUERY_IFACE]) != NULL) {
        ifname = blobmsg_get_string(c);
        iface_v4 = interface_get(ifname, SOCK_MC_IPV4);
        iface_v6 = interface_get(ifname, SOCK_MC_IPV6);
        if (!iface_v4 && !iface_v6)
            return -1;
    }

    if (!strcmp(method, "query")) {
        if (!iface_v4 && !iface_v6) {
            struct interface *iface;
            vlist_for_each_element(&interfaces, iface, node)
                dns_send_question(iface, NULL, question, type, 1);
        } else {
            if (iface_v4)
                dns_send_question(iface_v4, NULL, question, type, 1);
            if (iface_v6)
                dns_send_question(iface_v6, NULL, question, type, 1);
        }
        return 0;
    } else if (!strcmp(method, "fetch")) {
        if (!iface_v4 && !iface_v6)
            return -1;

        blob_buf_init(&fuzz_b, 0);
        void *k = blobmsg_open_array(&fuzz_b, "records");
        cache_dump_recursive(&fuzz_b, question, type, iface_v4 ? iface_v4 : iface_v6);
        blobmsg_close_array(&fuzz_b, k);
        return 0;
    }

    return -1;
}

static void setup_ipv4_interface(struct interface *iface, enum umdns_socket_type type) {
    memset(iface, 0, sizeof(*iface));
    iface->name = "fuzz0";
    iface->type = type;
    iface->ifindex = 1;
    iface->need_multicast = (type == SOCK_MC_IPV4);
    
    iface->addrs.n_addr = 1;
    iface->addrs.v4 = calloc(1, sizeof(*iface->addrs.v4));
    if (iface->addrs.v4) {
        inet_pton(AF_INET, "192.168.1.100", &iface->addrs.v4[0].addr);
        inet_pton(AF_INET, "255.255.255.0", &iface->addrs.v4[0].mask);
    }
}

static void setup_ipv6_interface(struct interface *iface, enum umdns_socket_type type) {
    memset(iface, 0, sizeof(*iface));
    iface->name = "fuzz0";
    iface->type = type;
    iface->ifindex = 1;
    iface->need_multicast = (type == SOCK_MC_IPV6);
    
    iface->addrs.n_addr = 1;
    iface->addrs.v6 = calloc(1, sizeof(*iface->addrs.v6));
    if (iface->addrs.v6) {
        inet_pton(AF_INET6, "fe80::1", &iface->addrs.v6[0].addr);
        inet_pton(AF_INET6, "ffff:ffff:ffff:ffff::", &iface->addrs.v6[0].mask);
    }
}

static void setup_ipv4_sockaddr(struct sockaddr_in *addr, uint16_t port) {
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    inet_pton(AF_INET, "192.168.1.50", &addr->sin_addr);
}

static void setup_ipv6_sockaddr(struct sockaddr_in6 *addr, uint16_t port) {
    memset(addr, 0, sizeof(*addr));
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(port);
    inet_pton(AF_INET6, "fe80::2", &addr->sin6_addr);
}

static bool validate_dns_packet(uint8_t *data, size_t size) {
    if (size < sizeof(struct dns_header)) {
        return false;
    }
    
    return true;
}

static struct blob_attr* create_browse_blob(uint8_t *data, size_t size) {
    static struct blob_buf browse_buf;
    blob_buf_init(&browse_buf, 0);
    
    if (size < 4) return browse_buf.head;
    
    uint8_t flags = data[0];
    size_t service_len = (size > 8) ? (data[1] % 32) : 0;

    if ((flags & 0x1) && service_len > 0 && size > service_len + 8) {
        char service_name[64] = {0};
        size_t copy_len = (service_len < 63) ? service_len : 63;
        memcpy(service_name, &data[8], copy_len);
        service_name[copy_len] = '\0';
        blobmsg_add_string(&browse_buf, "service", service_name);
    }
    
    if (flags & 0x2) {
        blobmsg_add_u8(&browse_buf, "array", (data[2] & 0x1));
    }
    
    if (flags & 0x4) {
        blobmsg_add_u8(&browse_buf, "address", (data[3] & 0x1));
    }
    
    return browse_buf.head;
}

static struct blob_attr* create_query_blob(uint8_t *data, size_t size) {
    static struct blob_buf query_buf;
    blob_buf_init(&query_buf, 0);
    
    if (size < 8) return query_buf.head;
    
    uint8_t flags = data[0];
    size_t question_len = (size > 16) ? (data[1] % 64) : 0;
    size_t iface_len = (size > 32) ? (data[2] % 16) : 0;
    uint32_t type_val = (data[3] << 8) | data[4];
    
    if ((flags & 0x1) && question_len > 0 && size > question_len + 16) {
        char question[128] = {0};
        size_t copy_len = (question_len < 127) ? question_len : 127;
        memcpy(question, &data[16], copy_len);
        question[copy_len] = '\0';
        blobmsg_add_string(&query_buf, "question", question);
    }
    
    if ((flags & 0x2) && iface_len > 0 && size > iface_len + 32) {
        char iface_name[32] = {0};
        size_t copy_len = (iface_len < 31) ? iface_len : 31;
        memcpy(iface_name, &data[32], copy_len);
        iface_name[copy_len] = '\0';
        blobmsg_add_string(&query_buf, "interface", iface_name);
    }
    
    if (flags & 0x4) {
        blobmsg_add_u32(&query_buf, "type", type_val);
    }
    
    return query_buf.head;
}

static void fuzz_dns_handle_packet_comprehensive(uint8_t *input, size_t size) {
    cache_init();
    
    if (size < 12) { // DNS header is 12 bytes minimum
        goto cleanup;
    }
    
    if (!validate_dns_packet(input, size)) {
        goto cleanup;
    }

    uint8_t config = input[0];
    uint8_t port_config = input[1];
    
    uint8_t *packet_data = input + 2;
    size_t packet_size = size - 2;
    
    for (int test_case = 0; test_case < 8; test_case++) {
        if ((config & (1 << test_case)) == 0) continue; 
        
        struct interface iface;
        union {
            struct sockaddr_in v4;
            struct sockaddr_in6 v6;
        } from;
        
        uint16_t port;
        
        switch (port_config & 0x3) {
            case 0: port = MCAST_PORT; break;
            case 1: port = 1024; break;
            case 2: port = 0; break;
            default: port = 65535; break;
        }
        port_config >>= 2;
        
        switch (test_case) {
            case 0:
                setup_ipv4_interface(&iface, SOCK_MC_IPV4);
                setup_ipv4_sockaddr(&from.v4, MCAST_PORT);
                dns_handle_packet(&iface, (struct sockaddr *)&from.v4, MCAST_PORT, packet_data, packet_size);
                break;
                
            case 1:
                setup_ipv4_interface(&iface, SOCK_UC_IPV4);
                setup_ipv4_sockaddr(&from.v4, MCAST_PORT);
                dns_handle_packet(&iface, (struct sockaddr *)&from.v4, MCAST_PORT, packet_data, packet_size);
                break;
                
            case 2:
                setup_ipv4_interface(&iface, SOCK_MC_IPV4);
                setup_ipv4_sockaddr(&from.v4, port);
                dns_handle_packet(&iface, (struct sockaddr *)&from.v4, port, packet_data, packet_size);
                break;
                
            case 3:
                setup_ipv4_interface(&iface, SOCK_UC_IPV4);
                setup_ipv4_sockaddr(&from.v4, port);
                dns_handle_packet(&iface, (struct sockaddr *)&from.v4, port, packet_data, packet_size);
                break;
                
            case 4:
                setup_ipv6_interface(&iface, SOCK_MC_IPV6);
                setup_ipv6_sockaddr(&from.v6, MCAST_PORT);
                dns_handle_packet(&iface, (struct sockaddr *)&from.v6, MCAST_PORT, packet_data, packet_size);
                break;
                
            case 5:
                setup_ipv6_interface(&iface, SOCK_UC_IPV6);
                setup_ipv6_sockaddr(&from.v6, MCAST_PORT);
                dns_handle_packet(&iface, (struct sockaddr *)&from.v6, MCAST_PORT, packet_data, packet_size);
                break;
                
            case 6:
                setup_ipv6_interface(&iface, SOCK_MC_IPV6);
                setup_ipv6_sockaddr(&from.v6, port);
                dns_handle_packet(&iface, (struct sockaddr *)&from.v6, port, packet_data, packet_size);
                break;
                
            case 7:
                setup_ipv6_interface(&iface, SOCK_UC_IPV6);
                setup_ipv6_sockaddr(&from.v6, port);
                dns_handle_packet(&iface, (struct sockaddr *)&from.v6, port, packet_data, packet_size);
                break;
        }
        
        if (interface_ipv6(&iface)) {
            free(iface.addrs.v6);
        } else {
            free(iface.addrs.v4);
        }
    }
    
cleanup:
    cache_cleanup(NULL);
}

static void fuzz_ubus_functions(uint8_t *input, size_t size) {
    if (size < 16) return;
    
    cache_init();
    get_hostname();
    
    uint8_t func_selector = input[0];
    uint8_t *fuzz_data = input + 1;
    size_t fuzz_size = size - 1;
    
    if (func_selector & 0x1) {
        struct blob_attr *browse_msg = create_browse_blob(fuzz_data, fuzz_size);
        if (browse_msg) {
            fuzz_umdns_browse(browse_msg);
        }
    }
    
    if (func_selector & 0x2) {
        struct blob_attr *query_msg = create_query_blob(fuzz_data, fuzz_size);
        if (query_msg) {
            fuzz_umdns_query(query_msg, "query");
        }
    }
    
    if (func_selector & 0x4) {
        struct blob_attr *query_msg = create_query_blob(fuzz_data, fuzz_size);
        if (query_msg) {
            fuzz_umdns_query(query_msg, "fetch");
        }
    }
    
    cache_cleanup(NULL);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    
    uint8_t *buf = malloc(size);
    if (!buf) {
        return 0;
    }
    
    memcpy(buf, data, size);
        uint8_t strategy = buf[0] % 3;
        
        switch (strategy) {
            case 0:
                fuzz_dns_handle_packet_comprehensive(buf, size);
                break;
            case 1:
                fuzz_ubus_functions(buf, size);
                break;
            case 2:
                fuzz_dns_handle_packet_comprehensive(buf, size);
                break;
            default:
                break;
        }
    free(buf);
    return 0;
}