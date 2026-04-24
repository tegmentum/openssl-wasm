#ifndef OPENSSL_WASM_SUPPORT_H
#define OPENSSL_WASM_SUPPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bindings/openssl.h"

static inline void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p && n) abort();
    return p;
}

static inline void list_u8_take(openssl_list_u8_t *out,
                                const uint8_t *src, size_t len) {
    out->ptr = xmalloc(len ? len : 1);
    if (len) memcpy(out->ptr, src, len);
    out->len = len;
}

static inline void string_take(openssl_string_t *out,
                               const char *src, size_t len) {
    out->ptr = xmalloc(len ? len : 1);
    if (len) memcpy(out->ptr, src, len);
    out->len = len;
}

#endif
