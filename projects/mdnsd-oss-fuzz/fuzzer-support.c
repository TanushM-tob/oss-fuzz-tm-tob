#include <stdarg.h>
#include <stdio.h>
#include <udebug.h>
#include "cache.h"
#include "util.h"

// Global udebug variables needed by main.c functions
static struct udebug ud;
static struct udebug_buf udb_log;
static const struct udebug_buf_meta meta_log = {
    .name = "umdns_log",
    .format = UDEBUG_FORMAT_STRING,
};

static struct udebug_ubus_ring rings[] = {
    {
        .buf = &udb_log,
        .meta = &meta_log,
        .default_entries = 1024,
        .default_size = 64 * 1024,
    }
};

static void
umdns_udebug_vprintf(const char *format, va_list ap)
{
    // In fuzzing mode, just use regular printf for debugging
    vprintf(format, ap);
}

void umdns_udebug_printf(const char *format, ...)
{
    va_list ap;
    
    va_start(ap, format);
    umdns_udebug_vprintf(format, ap);
    va_end(ap);
}

void umdns_udebug_config(struct udebug_ubus *ctx, struct blob_attr *data,
                        bool enabled)
{
    // Stub implementation for fuzzing
    (void)ctx; (void)data; (void)enabled;
} 