#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <json-c/json.h>

#include "jail/jail.h"
#include "jail/capabilities.h"
#include "jail/cgroups.h"
#include "jail/fs.h"
#include "jail/seccomp-oci.h"
#include "log.h"

extern int parseOCI(const char *jsonfile);
extern int parseOCIcapabilities(struct jail_capset *capset, struct blob_attr *msg);
extern struct sock_fprog *parseOCIlinuxseccomp(struct blob_attr *msg);

int jail_network_start(void *ctx, char *name, int pid) {
    return 0;
}

int jail_network_stop(void) {
    return 0;
}

size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t srclen = strlen(src);
    if (size > 0) {
        size_t copylen = (srclen < size - 1) ? srclen : size - 1;
        memcpy(dst, src, copylen);
        dst[copylen] = '\0';
    }
    return srclen;
}

static char temp_filename[256] = {0};
static struct blob_buf global_blob_buf;

enum vjson_state {
    VJSON_ERROR,
    VJSON_CONTINUE,
    VJSON_SUCCESS,
};

static enum vjson_state vjson_error(char **b, const char *fmt, ...) {
    if (b) *b = "fuzzer error";
    return VJSON_ERROR;
}

static void cleanup_temp_file(void) {
    if (temp_filename[0] != '\0') {
        unlink(temp_filename);
        temp_filename[0] = '\0';
    }
}

static int create_temp_json_file(const uint8_t *data, size_t size) {
    int fd;
    ssize_t written;

    strcpy(temp_filename, "/tmp/fuzz_config_XXXXXX");
    fd = mkstemp(temp_filename);
    if (fd == -1) {
        return -1;
    }

    written = write(fd, data, size);
    if (written != (ssize_t)size) {
        close(fd);
        cleanup_temp_file();
        return -1;
    }

    close(fd);
    return 0;
}

static int validate_oci_input(const uint8_t *data, size_t size) {
    bool has_brace = false;
    bool has_quote = false;

    for (size_t i = 0; i < size && i < 100; i++) {
        if (data[i] == '{' || data[i] == '}') {
            has_brace = true;
        }
        if (data[i] == '"') {
            has_quote = true;
        }
        if (data[i] == 0 && i < (size - 1)) {
            return 0;
        }
    }

    if (!has_brace && !has_quote) {
        return 0;
    }

    return 1;
}

static int validate_json_file_input(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    bool has_json_chars = false;
    for (size_t i = 0; i < size && i < 50; i++) {
        if (data[i] == '{' || data[i] == '[' || data[i] == '"') {
            has_json_chars = true;
            break;
        }
    }

    if (!has_json_chars) return 0;

    for (size_t i = 0; i < size - 1; i++) {
        if (data[i] == 0) return 0;
    }

    return 1;
}

static enum vjson_state vjson_parse_token(json_tokener *tok, char *buf, ssize_t len, char **err) {
    json_object *jsobj = NULL;

    jsobj = json_tokener_parse_ex(tok, buf, len);
    if (json_tokener_get_error(tok) == json_tokener_continue)
        return VJSON_CONTINUE;

    if (json_tokener_get_error(tok) == json_tokener_success) {
        if (json_object_get_type(jsobj) != json_type_object) {
            json_object_put(jsobj);
            return vjson_error(err, "result is not an JSON object");
        }

        blobmsg_add_object(&global_blob_buf, jsobj);
        json_object_put(jsobj);
        return VJSON_SUCCESS;
    }

    return vjson_error(err, "failed to parse JSON: %s (%d)",
        json_tokener_error_desc(json_tokener_get_error(tok)),
        json_tokener_get_error(tok));
}

static enum vjson_state vjson_parse_fuzz(const uint8_t *data, size_t size, char **err) {
    enum vjson_state r = VJSON_ERROR;
    size_t read_count = 0;
    char buf[64] = { 0 };
    json_tokener *tok;
    size_t pos = 0;

    tok = json_tokener_new();
    if (!tok)
        return vjson_error(err, "json_tokener_new() failed");

    blob_buf_init(&global_blob_buf, 0);
    vjson_error(err, "incomplete JSON input");

    while (pos < size) {
        size_t chunk_size = (size - pos > sizeof(buf)) ? sizeof(buf) : size - pos;
        memcpy(buf, data + pos, chunk_size);

        read_count += chunk_size;
        r = vjson_parse_token(tok, buf, chunk_size, err);
        if (r != VJSON_CONTINUE)
            break;

        memset(buf, 0, sizeof(buf));
        pos += chunk_size;
    }

    if (read_count == 0)
        vjson_error(err, "no JSON input");

    json_tokener_free(tok);
    return r;
}

static void fuzz_hotplug_handler(const uint8_t *data, size_t size) {
    int i = 0;
    char *buf = malloc(size + 1);
    void *index;

    if (!buf) return;

    memcpy(buf, data, size);
    buf[size] = '\0';

    blob_buf_init(&global_blob_buf, 0);
    index = blobmsg_open_table(&global_blob_buf, NULL);

    while (i < (int)size) {
        int l = strlen(buf + i) + 1;
        char *e = strstr(&buf[i], "=");

        if (e) {
            *e = '\0';
            blobmsg_add_string(&global_blob_buf, &buf[i], &e[1]);
        }
        i += l;
        if (l <= 0 || i >= (int)size) break;
    }

    blobmsg_close_table(&global_blob_buf, index);

    if (global_blob_buf.head) {}

    free(buf);
}

static int validate_hotplug_input(const uint8_t *data, size_t size) {
    if (size < 3) return 0;

    for (size_t i = 0; i < size - 1; i++) {
        if (data[i] == 0) return 0;
    }

    bool has_equals = false;
    for (size_t i = 0; i < size; i++) {
        if (data[i] == '=') {
            has_equals = true;
            break;
        }
    }

    return has_equals ? 1 : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0;
    }

    uint8_t pick = data[0] % 4;
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;

    switch (pick) {
        case 0: {
            if (!validate_oci_input(fuzz_data, fuzz_size)) {
                return 0;
            }

            if (create_temp_json_file(fuzz_data, fuzz_size) != 0) {
                return 0;
            }

            parseOCI(temp_filename);
            cleanup_temp_file();
            break;
        }

        case 1: {
            if (!validate_json_file_input(fuzz_data, fuzz_size)) {
                return 0;
            }

            if (create_temp_json_file(fuzz_data, fuzz_size) != 0) {
                return 0;
            }

            blob_buf_init(&global_blob_buf, 0);
            blobmsg_add_json_from_file(&global_blob_buf, temp_filename);

            struct sock_fprog *prog = parseOCIlinuxseccomp(global_blob_buf.head);
            if (prog) {
                free(prog);
            }

            struct jail_capset capset = {0};
            parseOCIcapabilities(&capset, global_blob_buf.head);

            cleanup_temp_file();
            break;
        }

        case 2: {
            if (!validate_json_file_input(fuzz_data, fuzz_size)) {
                return 0;
            }

            char *err = NULL;
            vjson_parse_fuzz(fuzz_data, fuzz_size, &err);
            break;
        }

        case 3: {
            if (!validate_hotplug_input(fuzz_data, fuzz_size)) {
                return 0;
            }

            fuzz_hotplug_handler(fuzz_data, fuzz_size);
            break;
        }
    }

    return 0;
}
