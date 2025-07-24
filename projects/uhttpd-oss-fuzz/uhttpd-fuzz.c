
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
#include <limits.h>
#include <sys/mman.h>
#include <libubox/blobmsg.h>
#include "uhttpd.h"

#ifndef __HDR_MAX
#define __HDR_MAX 16
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

extern struct config conf;

// Mock write function that can fail
static int mock_failing_write(struct ustream *s, const char *buf, int len, bool more) {
    static int fail_counter = 0;
    if (++fail_counter % 3 == 0) {
        errno = (fail_counter % 2) ? ENOSPC : EPIPE;
        return -1;
    }
    return len;
}

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

static void reset_config_lists(void) {
    /* Reset config lists to prevent segfault in uh_handle_alias
     * when fuzzing corrupts the list structures */
    INIT_LIST_HEAD(&conf.cgi_alias);
    INIT_LIST_HEAD(&conf.lua_prefix);
#ifdef HAVE_UCODE
    INIT_LIST_HEAD(&conf.ucode_prefix);
#endif
}

static void fuzz_config_from_data(const uint8_t *data, size_t size) {
    // Always use safe defaults first
    conf.script_timeout = 60;
    conf.network_timeout = 30;
    conf.http_keepalive = 20;
    conf.max_script_requests = 3;
    conf.max_connections = 100;
    conf.docroot = "/tmp";
    conf.cgi_prefix = "/cgi-bin";
    conf.cgi_prefix_len = strlen(conf.cgi_prefix);
    
    // Only modify if we have valid data and enough bytes
    if (!data || size < 8) {
        return;
    }
    
         // Vary configuration based on fuzz data with bounds checking
     conf.script_timeout = 1 + (data[0] % 300);
     conf.network_timeout = 1 + (data[1] % 120);
     conf.http_keepalive = data[2] % 300;
     conf.max_script_requests = 1 + (data[3] % 100);
     conf.max_connections = 1 + (data[4] % 1000);
     // Skip data[5] - max_request_size field doesn't exist
    
         // Ensure docroot is always set (critical for path lookup)
     conf.docroot = "/tmp";
     
     // Vary CGI prefix - ensure we don't access beyond size
     if (size > 6) {
         if (data[6] & 1) {
             conf.cgi_prefix = "/cgi-bin";
         } else if (data[6] & 2) {
             conf.cgi_prefix = "/scripts";
         } else if (data[6] & 4) {
             conf.cgi_prefix = "/../../../etc/passwd";
         } else {
             conf.cgi_prefix = "/";
         }
         conf.cgi_prefix_len = strlen(conf.cgi_prefix);
     }
}

static void init_client(struct client *cl, const uint8_t *data, size_t size) {
    memset(cl, 0, sizeof(*cl));
    
    // Check blob_buf_init return values
    if (blob_buf_init(&cl->hdr, 0) < 0) {
        // Fall back to memset if blob_buf_init fails
        memset(&cl->hdr, 0, sizeof(cl->hdr));
    }
    if (blob_buf_init(&cl->hdr_response, 0) < 0) {
        memset(&cl->hdr_response, 0, sizeof(cl->hdr_response));
    }
    
    cl->state = CLIENT_STATE_HEADER;
    cl->id = 1;
    
    // Fuzz protocol version and method with bounds checking
    if (size >= 2 && data) {
        cl->request.version = data[0] % 3; // UH_HTTP_VER_0_9 to UH_HTTP_VER_1_1 (0-2)
        cl->request.method = data[1] % 7;  // UH_HTTP_MSG_GET to UH_HTTP_MSG_DELETE (0-6)
    } else {
        cl->request.version = UH_HTTP_VER_1_1;
        cl->request.method = UH_HTTP_MSG_GET;
    }
    
    memset(&cl->timeout, 0, sizeof(cl->timeout));
    memset(&cl->dispatch, 0, sizeof(cl->dispatch));
    cl->us = &cl->sfd.stream;
    
         // Create a real temporary file for testing
#ifdef __linux__
     cl->sfd.fd.fd = memfd_create("uhttpd_fuzz", 0);
     if (cl->sfd.fd.fd < 0)
#endif
     {
         cl->sfd.fd.fd = open("/tmp/uhttpd_fuzz_fd", O_RDWR | O_CREAT | O_TRUNC, 0600);
     }
     if (cl->sfd.fd.fd < 0) {
         cl->sfd.fd.fd = STDOUT_FILENO;
     }
    
    // Initialize ustream carefully
    memset(&cl->sfd, 0, sizeof(cl->sfd));
    cl->sfd.fd.fd = (cl->sfd.fd.fd >= 0) ? cl->sfd.fd.fd : STDOUT_FILENO;
    ustream_fd_init(&cl->sfd, cl->sfd.fd.fd);
    
    // Sometimes inject write failures with bounds checking
    if (size > 2 && data && (data[2] & 0x80)) {
        cl->sfd.stream.write = mock_failing_write;
    }
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

 static void add_headers_to_client(struct client *cl, const uint8_t *data, size_t size) {
     size_t offset = 0;
     int header_count = 0;
     
     while (offset < size && header_count < 20) { // Limit headers
         // Find next null or newline
         size_t header_len = 0;
         while (offset + header_len < size && 
                data[offset + header_len] != '\0' && 
                data[offset + header_len] != '\n' &&
                header_len < 512) { // Smaller limit
             header_len++;
         }
         
         if (header_len > 10) { // Must have minimum header format "name: val"
             // Create safe header copy
             char *header = malloc(header_len + 1);
             if (header) {
                 // Safely copy and sanitize header
                 for (size_t i = 0; i < header_len; i++) {
                     char c = data[offset + i];
                     // Replace dangerous chars but preserve colon
                     if (c == '\0' || c == '\n' || c == '\r') {
                         c = '_';
                     }
                     header[i] = c;
                 }
                 header[header_len] = '\0';
                 
                 // Only parse if it looks like a valid header (has colon)
                 if (strchr(header, ':') != NULL) {
                     client_parse_header(cl, header);
                     header_count++;
                 }
                 free(header);
             }
         }
         
         offset += header_len + 1;
         if (offset >= size) break;
     }
 }

static void init_path_info_fuzzed(struct path_info *pi, const uint8_t *data, size_t size) {
    memset(pi, 0, sizeof(*pi));
    
    if (size < 16) {
        pi->root = "/tmp";
        pi->phys = "/tmp/nonexistent";
        pi->name = "fuzz";
        pi->info = "";
        pi->query = "";
        return;
    }
    
    size_t offset = 0;
    
    // Fuzz root path
    static char root_buf[256];
    size_t root_len = data[offset] % 64;
    offset++;
    if (offset + root_len <= size) {
        memcpy(root_buf, data + offset, root_len);
        root_buf[root_len] = '\0';
        pi->root = root_buf;
        offset += root_len;
    } else {
        pi->root = "/tmp";
    }
    
    // Fuzz physical path - allow path traversal attempts
    static char phys_buf[512];
    size_t phys_len = data[offset] % 200;
    offset++;
    if (offset + phys_len <= size) {
        memcpy(phys_buf, data + offset, phys_len);
        phys_buf[phys_len] = '\0';
        pi->phys = phys_buf;
        offset += phys_len;
    } else {
        pi->phys = "/tmp/fuzz";
    }
    
    // Fuzz query string
    static char query_buf[1024];
    size_t query_len = data[offset] % 512;
    offset++;
    if (offset + query_len <= size) {
        memcpy(query_buf, data + offset, query_len);
        query_buf[query_len] = '\0';
        pi->query = query_buf;
        offset += query_len;
    } else {
        pi->query = "";
    }
    
    // Fuzz stat structure
    if (offset + 8 <= size) {
        pi->stat.st_mode = *(uint32_t*)(data + offset);
        pi->stat.st_size = *(uint32_t*)(data + offset + 4);
        offset += 8;
    }
    
    // Fuzz interpreter
    if (offset < size && (data[offset] & 1)) {
        static struct interpreter fuzz_interpreter;
        static char interp_path[64];
        static char interp_ext[16];
        
        size_t path_len = (data[offset] >> 1) % 32;
        offset++;
        if (offset + path_len <= size) {
            memcpy(interp_path, data + offset, path_len);
            interp_path[path_len] = '\0';
            fuzz_interpreter.path = interp_path;
            offset += path_len;
        }
        
        size_t ext_len = data[offset] % 8;
        offset++;
        if (offset + ext_len <= size) {
            memcpy(interp_ext, data + offset, ext_len);
            interp_ext[ext_len] = '\0';
            fuzz_interpreter.ext = interp_ext;
        }
        
        pi->ip = &fuzz_interpreter;
    }
}

 static void fuzz_post_data(struct client *cl, const uint8_t *data, size_t size) {
     // Add Content-Length header
     char content_length[32];
     snprintf(content_length, sizeof(content_length), "Content-Length: %zu", size);
     client_parse_header(cl, content_length);
     
     // Add Content-Type based on fuzz data
     if (size > 0) {
         switch (data[0] % 4) {
             case 0:
                 {
                     char content_type[] = "Content-Type: application/x-www-form-urlencoded";
                     client_parse_header(cl, content_type);
                 }
                 break;
             case 1:
                 {
                     char content_type[] = "Content-Type: multipart/form-data; boundary=----FuzzBoundary";
                     client_parse_header(cl, content_type);
                 }
                 break;
             case 2:
                 {
                     char content_type[] = "Content-Type: application/json";
                     client_parse_header(cl, content_type);
                 }
                 break;
             case 3:
                 {
                     char content_type[] = "Content-Type: application/octet-stream";
                     client_parse_header(cl, content_type);
                 }
                 break;
         }
     }
     
     // Set POST method
     cl->request.method = UH_HTTP_MSG_POST;
 }

 static void fuzz_chunked_encoding(struct client *cl, const uint8_t *data, size_t size) {
     char transfer_encoding[] = "Transfer-Encoding: chunked";
     client_parse_header(cl, transfer_encoding);
     
     // Just add a simple Content-Length header instead of simulating chunks
     char content_length[32];
     snprintf(content_length, sizeof(content_length), "Content-Length: %zu", size);
     client_parse_header(cl, content_length);
 }

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    init_defaults_pre();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Input validation - need at least 9 bytes (1 for test_selector + 8 for config)
    if (size < 9 || size > 65536) return 0;  // Reasonable size limits
    if (!data) return 0;
    
    // Additional pointer validation
    if ((void*)data == NULL || size == 0) return 0;
    
    uint8_t test_selector = data[0] % 12; // More test cases
    const uint8_t *test_data = data + 1;
    size_t test_size = size - 1;
    
    // Validate test_data pointer arithmetic
    if (test_size == 0 || test_data < data || 
        (void*)test_data >= (void*)(data + size)) {
        return 0;
    }
    
    // Reset global state to prevent corruption
    reset_config_lists();
    
    // Vary configuration for each test
    fuzz_config_from_data(test_data, test_size);
    
    struct client cl;
    init_client(&cl, test_data, test_size);
    
    // Validate client initialization succeeded
    if (cl.sfd.fd.fd < 0) {
        cleanup_client(&cl);
        return 0;
    }
    
    switch (test_selector) {
        case 0: // Raw header parsing
            add_headers_to_client(&cl, test_data, test_size);
            break;
            
                 case 1: // File request with raw URL
             if (test_size > 0 && test_size < 2048) { // Reasonable URL size limit
                 char *url = malloc(test_size + 2); // Extra space for leading slash
                 if (url) {
                     // Ensure URL starts with /
                     url[0] = '/';
                     size_t url_pos = 1;
                     
                     // Sanitize URL characters
                     for (size_t i = 0; i < test_size && url_pos < test_size; i++) {
                         char c = test_data[i];
                         // Allow reasonable URL characters
                         if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
                             (c >= '0' && c <= '9') || c == '/' || c == '.' || 
                             c == '-' || c == '_' || c == '~' || c == '%' || 
                             c == '?' || c == '&' || c == '=') {
                             url[url_pos++] = c;
                         }
                     }
                     url[url_pos] = '\0';
                     
                     bool is_error_handler = (test_size > 0) ? (test_data[0] & 1) : false;
                     __handle_file_request(&cl, url, is_error_handler);
                     free(url);
                 }
             }
             break;
            
                 case 2: // URL decoding with raw data
             if (test_size > 0 && test_size < 1024 && test_data) {
                 // Validate test_data pointer before use
                 if ((void*)test_data < (void*)data || 
                     (void*)test_data >= (void*)(data + size)) {
                     break; // Invalid pointer, skip this test
                 }
                 
                 // Create null-terminated input for uh_urldecode
                 char *input = malloc(test_size + 1);
                 char *output = malloc(test_size * 3 + 1); // Worst case expansion
                 if (input && output) {
                     // Sanitize input for URL decoding with extra bounds checking
                     for (size_t i = 0; i < test_size; i++) {
                         // Double-check bounds to prevent segfault
                         if ((void*)(test_data + i) >= (void*)(data + size)) {
                             break; // Out of bounds, stop copying
                         }
                         char c = test_data[i];
                         // Replace null bytes
                         if (c == '\0') c = '_';
                         input[i] = c;
                     }
                     input[test_size] = '\0';
                     
                     uh_urldecode(output, test_size * 3, input, test_size);
                 }
                 if (input) free(input);
                 if (output) free(output);
             }
             break;
            
                 case 3: // Full request handling
             if (test_size > 0 && test_size < 2048) {
                 char *url = malloc(test_size + 2);
                 if (url) {
                     // Create safe URL
                     url[0] = '/';
                     size_t url_pos = 1;
                     
                     for (size_t i = 0; i < test_size && url_pos < test_size; i++) {
                         char c = test_data[i];
                         if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
                             (c >= '0' && c <= '9') || c == '/' || c == '.' || 
                             c == '-' || c == '_' || c == '~' || c == '%' || 
                             c == '?' || c == '&' || c == '=') {
                             url[url_pos++] = c;
                         }
                     }
                     url[url_pos] = '\0';
                     
                     blobmsg_add_string(&cl.hdr, "URL", url);
                     
                     // Reset config lists to prevent crashes
                     reset_config_lists();
                     
                     uh_handle_request(&cl);
                     free(url);
                 }
             }
             break;
            
                 case 4: // CGI handling with fuzzed path_info
             if (test_size >= 4 && test_size < 2048) {
                 size_t url_size = test_size / 3;
                 if (url_size > 0) {
                     char *url = malloc(url_size + 2);
                     if (url) {
                         // Create safe URL
                         url[0] = '/';
                         size_t url_pos = 1;
                         
                         for (size_t i = 0; i < url_size && url_pos < url_size; i++) {
                             char c = test_data[i];
                             if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
                                 (c >= '0' && c <= '9') || c == '/' || c == '.' || 
                                 c == '-' || c == '_') {
                                 url[url_pos++] = c;
                             }
                         }
                         url[url_pos] = '\0';
                         
                         struct path_info pi;
                         size_t pi_size = test_size - url_size;
                         init_path_info_fuzzed(&pi, test_data + url_size, pi_size);
                         cgi_handle_request(&cl, url, &pi);
                         free(url);
                     }
                 }
             }
             break;
            
                 case 5: // POST request handling
             fuzz_post_data(&cl, test_data, test_size);
             reset_config_lists();
             uh_handle_request(&cl);
             break;
            
        case 6: // Chunked transfer encoding
            fuzz_chunked_encoding(&cl, test_data, test_size);
            break;
            
                 case 7: // Authentication header fuzzing
             if (test_size > 0) {
                 char auth_header[1024];
                 const char *auth_types[] = {"Basic", "Digest", "Bearer", "NTLM"};
                 int auth_type = test_data[0] % 4;
                 
                 // Safely create auth header without embedded nulls
                 snprintf(auth_header, sizeof(auth_header), "Authorization: %s ", auth_types[auth_type]);
                 size_t prefix_len = strlen(auth_header);
                 
                 // Safely append credential data, replacing dangerous chars
                 size_t max_cred_size = sizeof(auth_header) - prefix_len - 1;
                 size_t cred_size = (test_size - 1 > max_cred_size) ? max_cred_size : test_size - 1;
                 
                 for (size_t i = 0; i < cred_size; i++) {
                     char c = test_data[1 + i];
                     // Replace null bytes and dangerous chars
                     if (c == '\0' || c == '\n' || c == '\r') {
                         c = '_';
                     }
                     auth_header[prefix_len + i] = c;
                 }
                 auth_header[prefix_len + cred_size] = '\0';
                 
                 client_parse_header(&cl, auth_header);
                 reset_config_lists();
                 uh_handle_request(&cl);
             }
             break;
            
                 case 8: // Cookie parsing
             if (test_size > 0) {
                 char cookie_header[2048];
                 snprintf(cookie_header, sizeof(cookie_header), "Cookie: ");
                 size_t prefix_len = strlen(cookie_header);
                 
                 // Safely append cookie data
                 size_t max_copy_len = sizeof(cookie_header) - prefix_len - 1;
                 size_t copy_len = (test_size > max_copy_len) ? max_copy_len : test_size;
                 
                 for (size_t i = 0; i < copy_len; i++) {
                     char c = test_data[i];
                     // Replace null bytes and line terminators
                     if (c == '\0' || c == '\n' || c == '\r') {
                         c = '_';
                     }
                     cookie_header[prefix_len + i] = c;
                 }
                 cookie_header[prefix_len + copy_len] = '\0';
                 
                 client_parse_header(&cl, cookie_header);
             }
             break;
            
        case 9: // Range request fuzzing
            if (test_size >= 8) {
                uint32_t start = *(uint32_t*)test_data;
                uint32_t end = *(uint32_t*)(test_data + 4);
                                 char range_header[128];
                 snprintf(range_header, sizeof(range_header), "Range: bytes=%u-%u", start, end);
                 client_parse_header(&cl, range_header);
                 reset_config_lists();
                 uh_handle_request(&cl);
             }
             break;
            
                 case 10: // WebSocket upgrade
             {
                 char upgrade_hdr[] = "Upgrade: websocket";
                 char connection_hdr[] = "Connection: Upgrade";
                 char ws_key_hdr[] = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==";
                 char ws_version_hdr[] = "Sec-WebSocket-Version: 13";
                 
                 client_parse_header(&cl, upgrade_hdr);
                 client_parse_header(&cl, connection_hdr);
                 client_parse_header(&cl, ws_key_hdr);
                 client_parse_header(&cl, ws_version_hdr);
                 reset_config_lists();
                 uh_handle_request(&cl);
             }
             break;
            
                case 11: // Multiple headers with same name
            if (test_size > 0) {
                for (int i = 0; i < 10 && i < test_size; i++) {
                    char header[256];
                    // Safely limit header data to prevent buffer overflow
                    int max_data_len = sizeof(header) - 50; // Reserve space for prefix
                    int actual_data_len = (test_size - i > max_data_len) ? max_data_len : (test_size - i);
                    
                    snprintf(header, sizeof(header), "X-Fuzz-%d: %.*s", 
                             i, actual_data_len, test_data + i);
                    
                    // Ensure null termination and no embedded nulls
                    header[sizeof(header) - 1] = '\0';
                    for (int j = 0; header[j] != '\0'; j++) {
                        if (header[j] == '\0' && j < strlen("X-Fuzz-X: ")) {
                            header[j] = '_';
                        }
                    }
                    
                    client_parse_header(&cl, header);
                }
                reset_config_lists();
                uh_handle_request(&cl);
            }
            break;
    }
    
    cleanup_client(&cl);
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
