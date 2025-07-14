/* Weak aliases for optional udebug_ubus helpers so that the
 * project links even when libudebug with ubus support is not built.
 */
#include <stdbool.h>
struct blob_attr;
struct ubus_context;
struct udebug_ubus;
__attribute__((weak)) void udebug_ubus_init(struct udebug_ubus *ctx, struct ubus_context *u, const char *s, void *cb) {}
__attribute__((weak)) void udebug_ubus_free(struct udebug_ubus *ctx) {}
__attribute__((weak)) void udebug_ubus_apply_config(void *ud, void *rings, int n, struct blob_attr *data, bool enabled) {}
__attribute__((weak)) void udebug_ubus_ring_init(void *ud, void *ring) {} 