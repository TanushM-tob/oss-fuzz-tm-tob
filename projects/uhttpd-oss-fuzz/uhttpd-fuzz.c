#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <libubox/blobmsg.h>
#include "uhttpd.h"

#ifndef __HDR_MAX
#define __HDR_MAX 16
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

extern struct config conf;

static void init_defaults_pre(void) {
    memset(&conf, 0, sizeof(conf));
    conf.script_timeout = 60;
    conf.network_timeout = 30;
    conf.http_keepalive = 20;
    conf.max_script_requests = 3;
    conf.max_connections = 100;
    conf.realm = "Protected Area";
    conf.cgi_prefix = "/cgi-bin";
    conf.cgi_path = "/sbin:/usr/sbin:/bin:/usr/bin";
    conf.docroot = "/tmp";
    conf.cgi_prefix_len = strlen(conf.cgi_prefix);
    INIT_LIST_HEAD(&conf.cgi_alias);
    INIT_LIST_HEAD(&conf.lua_prefix);
#ifdef HAVE_UCODE
    INIT_LIST_HEAD(&conf.ucode_prefix);
#endif
}

static void init_client(struct client *cl) {
    memset(cl, 0, sizeof(*cl));
    blob_buf_init(&cl->hdr, 0);
    blob_buf_init(&cl->hdr_response, 0);
    cl->state = CLIENT_STATE_HEADER;
    cl->id = 1;
    memset(&cl->request, 0, sizeof(cl->request));
    cl->request.version = UH_HTTP_VER_1_1;
    cl->request.method = UH_HTTP_MSG_GET;
    memset(&cl->timeout, 0, sizeof(cl->timeout));
    memset(&cl->dispatch, 0, sizeof(cl->dispatch));
    cl->us = &cl->sfd.stream;
    cl->sfd.fd.fd = open("/dev/null", O_WRONLY);
    if (cl->sfd.fd.fd < 0) cl->sfd.fd.fd = STDOUT_FILENO;
    ustream_fd_init(&cl->sfd, cl->sfd.fd.fd);
}

static void cleanup_client(struct client *cl) {
    if (cl->dispatch.free) {
        cl->dispatch.free(cl);
    }
    if (cl->dispatch.close_fds) {
        cl->dispatch.close_fds(cl);
    }
    if (cl->timeout.cb) {
        uloop_timeout_cancel(&cl->timeout);
    }
    blob_buf_free(&cl->hdr);
    blob_buf_free(&cl->hdr_response);
    if (cl->sfd.fd.fd > STDERR_FILENO) {
        close(cl->sfd.fd.fd);
    }
    ustream_free(&cl->sfd.stream);
}

static void add_url_to_client(struct client *cl, const char *url) {
    if (!url || !*url) {
        url = "/";
    }
    blobmsg_add_string(&cl->hdr, "URL", url);
}

static char* sanitize_header_data(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *header = malloc(size + 1);
    if (!header) return NULL;
    for (size_t i = 0; i < size; i++) {
        if (data[i] >= 32 && data[i] <= 126) {
            header[i] = data[i];
        } else if (data[i] == '\t' || data[i] == ' ') {
            header[i] = data[i];
        } else {
            header[i] = '_';
        }
    }
    header[size] = '\0';
    char *colon = strchr(header, ':');
    if (!colon && size > 10) {
        header[size/2] = ':';
    }
    return header;
}

static char* sanitize_url_data(const uint8_t *data, size_t size) {
    if (size == 0) return strdup("/");
    char *url = malloc(size + 2);
    if (!url) return NULL;
    url[0] = '/';
    size_t url_len = 1;
    for (size_t i = 0; i < size && url_len < size; i++) {
        char c = data[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || c == '/' || c == '.' || 
            c == '-' || c == '_' || c == '~' || c == '%' || 
            c == '?' || c == '&' || c == '=') {
            url[url_len++] = c;
        }
    }
    url[url_len] = '\0';
    return url;
}

static char* sanitize_urldecode_data(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *input = malloc(size + 1);
    if (!input) return NULL;
    for (size_t i = 0; i < size; i++) {
        char c = data[i];
        if ((c >= 32 && c <= 126)) {
            input[i] = c;
        } else {
            input[i] = '%';
        }
    }
    input[size] = '\0';
    return input;
}

static void init_path_info(struct path_info *pi, const uint8_t *data, size_t size) {
    memset(pi, 0, sizeof(*pi));
    if (size < 4) {
        pi->root = "/tmp/uhttpd_fuzz";
        pi->phys = "/tmp/uhttpd_fuzz/nonexistent_test.cgi";
        pi->name = "nonexistent_test.cgi";
        pi->info = "";
        pi->query = "";
        pi->redirected = false;
        pi->ip = NULL;
        memset(&pi->stat, 0, sizeof(pi->stat));
        pi->stat.st_mode = S_IFREG | S_IXOTH | S_IRUSR | S_IWUSR | S_IXUSR;
        return;
    }
    uint8_t flags = data[0];
    const uint8_t *path_data = data + 1;
    size_t path_size = size - 1;
    pi->root = "/tmp/uhttpd_fuzz";
    pi->name = "fuzz_script.cgi";
    pi->info = "";
    pi->query = (flags & 0x01) ? "param=fuzzing&value=test" : "";
    pi->redirected = (flags & 0x02) ? true : false;
    static char phys_path[256];
    snprintf(phys_path, sizeof(phys_path), "/tmp/uhttpd_fuzz/nonexistent_fuzz_%02x.cgi", flags);
    pi->phys = phys_path;
    memset(&pi->stat, 0, sizeof(pi->stat));
    if (flags & 0x04) {
        pi->stat.st_mode = S_IFREG | S_IXOTH | S_IRUSR | S_IWUSR | S_IXUSR;
    } else {
        pi->stat.st_mode = S_IFREG | S_IRUSR | S_IWUSR;
    }
    pi->stat.st_size = (path_size > 0) ? (path_data[0] % 10) * 1024 : 1024;
    if (flags & 0x08) {
        static struct interpreter mock_interpreter = {
            .path = "/bin/false",
            .ext = ".cgi"
        };
        pi->ip = &mock_interpreter;
    } else {
        pi->ip = NULL;
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    init_defaults_pre();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    
    uint8_t test_selector = data[0] % 5;
    const uint8_t *test_data = data + 1;
    size_t test_size = size - 1;
    
    struct client cl;
    init_client(&cl);
    
    switch (test_selector) {
        case 0: {
            char *header_data = sanitize_header_data(test_data, test_size);
            if (header_data) {
                client_parse_header(&cl, header_data);
                free(header_data);
            }
            break;
        }
        case 1: {
            char *url_data = sanitize_url_data(test_data, test_size);
            if (url_data) {
                bool is_error_handler = (test_size > 0) ? (test_data[0] & 1) : false;
                __handle_file_request(&cl, url_data, is_error_handler);
                free(url_data);
            }
            break;
        }
        case 2: {
            char *input_data = sanitize_urldecode_data(test_data, test_size);
            if (input_data) {
                char output_buf[4096];
                uh_urldecode(output_buf, sizeof(output_buf), input_data, strlen(input_data));
                free(input_data);
            }
            break;
        }
        case 3: {
            char *url_data = sanitize_url_data(test_data, test_size);
            if (url_data) {
                add_url_to_client(&cl, url_data);
                uh_handle_request(&cl);
                free(url_data);
            }
            break;
        }
        case 4: {
            if (test_size >= 2) {
                size_t url_size = test_size / 2;
                size_t pi_size = test_size - url_size;
                char *url_data = sanitize_url_data(test_data, url_size);
                if (url_data) {
                    struct path_info pi;
                    init_path_info(&pi, test_data + url_size, pi_size);
                    cgi_handle_request(&cl, url_data, &pi);
                    free(url_data);
                }
            }
            break;
        }
    }
    cleanup_client(&cl);
    return 0;
}
