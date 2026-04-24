// mac interface implementation — HMAC, CMAC, KMAC, Poly1305, SipHash, GMAC.
//
// Backed by EVP_MAC from libcrypto. Each algorithm maps to a named
// EVP_MAC fetched from the default provider.

#include "bindings/openssl.h"
#include "include/support.h"
#include "include/algs.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#define MAC_ERR_UNSUPPORTED EXPORTS_OPENSSL_COMPONENT_MAC_MAC_ERROR_UNSUPPORTED_ALGORITHM
#define MAC_ERR_BAD_KEY     EXPORTS_OPENSSL_COMPONENT_MAC_MAC_ERROR_BAD_KEY_SIZE
#define MAC_ERR_BAD_NONCE   EXPORTS_OPENSSL_COMPONENT_MAC_MAC_ERROR_BAD_NONCE_SIZE
#define MAC_ERR_MISSING     EXPORTS_OPENSSL_COMPONENT_MAC_MAC_ERROR_MISSING_PARAMETER
#define MAC_ERR_INTERNAL    EXPORTS_OPENSSL_COMPONENT_MAC_MAC_ERROR_INTERNAL

static const char *mac_name(exports_openssl_component_mac_algorithm_t a) {
    switch (a) {
    case 0: return "HMAC";
    case 1: return "CMAC";
    case 2: return "KMAC-128";
    case 3: return "KMAC-256";
    case 4: return "Poly1305";
    case 5: return "SIPHASH";
    case 6: return "GMAC";
    default: return NULL;
    }
}

static const char *block_cipher_name(exports_openssl_component_mac_block_cipher_t c) {
    switch (c) {
    case 0: return "AES-128-CBC";
    case 1: return "AES-192-CBC";
    case 2: return "AES-256-CBC";
    default: return NULL;
    }
}

static const char *gmac_cipher_name(exports_openssl_component_mac_block_cipher_t c) {
    switch (c) {
    case 0: return "AES-128-GCM";
    case 1: return "AES-192-GCM";
    case 2: return "AES-256-GCM";
    default: return NULL;
    }
}

// Build an OSSL_PARAM array appropriate for the given MAC algorithm +
// WIT params variant. Returns the number of real params written (excluding
// the trailing terminator). `out` must be large enough (we use 6).
static int build_mac_params(
        exports_openssl_component_mac_algorithm_t alg,
        const exports_openssl_component_mac_params_t *p,
        OSSL_PARAM *out, size_t cap,
        exports_openssl_component_mac_mac_error_t *err) {
    size_t i = 0;
    (void)cap;
    switch (alg) {
    case 0: { // HMAC
        if (p->tag != EXPORTS_OPENSSL_COMPONENT_MAC_PARAMS_HMAC) {
            err->tag = MAC_ERR_MISSING; return -1;
        }
        const char *dname = wit_digest_name(p->val.hmac.hash);
        if (!dname) { err->tag = MAC_ERR_UNSUPPORTED; return -1; }
        out[i++] = OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST, (char *)dname, 0);
        break;
    }
    case 1: { // CMAC
        if (p->tag != EXPORTS_OPENSSL_COMPONENT_MAC_PARAMS_CMAC) {
            err->tag = MAC_ERR_MISSING; return -1;
        }
        const char *cname = block_cipher_name(p->val.cmac.cipher);
        if (!cname) { err->tag = MAC_ERR_UNSUPPORTED; return -1; }
        out[i++] = OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_CIPHER, (char *)cname, 0);
        break;
    }
    case 2: // KMAC-128
    case 3: { // KMAC-256
        if (p->tag != EXPORTS_OPENSSL_COMPONENT_MAC_PARAMS_KMAC) {
            err->tag = MAC_ERR_MISSING; return -1;
        }
        if (p->val.kmac.customization.is_some) {
            out[i++] = OSSL_PARAM_construct_octet_string(
                OSSL_MAC_PARAM_CUSTOM,
                p->val.kmac.customization.val.ptr,
                p->val.kmac.customization.val.len);
        }
        // OSSL_PARAM_construct_size_t needs a non-const size_t pointer.
        // EVP_MAC_init reads this value synchronously, so a stack-local
        // here is safe even though the pointer nominally outlives this
        // call — we're passed `out` by reference and the caller invokes
        // EVP_MAC_init before returning. We scope `scratch_size` into
        // the rest of the switch by caller reading `p->val.kmac.output_len`
        // through a local size_t in the outer function. To keep the
        // lifetime crystal-clear, require the caller to own that buffer.
        //
        // For simplicity we use a static buffer here. This is safe
        // because (a) wasi is single-threaded, (b) EVP_MAC_init copies
        // the value immediately into the MAC context before returning.
        static size_t kmac_size_scratch;
        kmac_size_scratch = p->val.kmac.output_len;
        out[i++] = OSSL_PARAM_construct_size_t(
            OSSL_MAC_PARAM_SIZE, &kmac_size_scratch);
        break;
    }
    case 4: // Poly1305
    case 5: // SIPHASH
        /* No params needed. */
        break;
    case 6: { // GMAC
        if (p->tag != EXPORTS_OPENSSL_COMPONENT_MAC_PARAMS_GMAC) {
            err->tag = MAC_ERR_MISSING; return -1;
        }
        const char *cname = gmac_cipher_name(p->val.gmac.cipher);
        if (!cname) { err->tag = MAC_ERR_UNSUPPORTED; return -1; }
        out[i++] = OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_CIPHER, (char *)cname, 0);
        out[i++] = OSSL_PARAM_construct_octet_string(
            OSSL_MAC_PARAM_IV,
            p->val.gmac.nonce.ptr, p->val.gmac.nonce.len);
        break;
    }
    default:
        err->tag = MAC_ERR_UNSUPPORTED;
        return -1;
    }
    out[i] = OSSL_PARAM_construct_end();
    return (int)i;
}

static EVP_MAC_CTX *new_mac_ctx(
        exports_openssl_component_mac_algorithm_t alg,
        const openssl_list_u8_t *key,
        const exports_openssl_component_mac_params_t *p,
        exports_openssl_component_mac_mac_error_t *err) {
    const char *name = mac_name(alg);
    if (!name) { err->tag = MAC_ERR_UNSUPPORTED; return NULL; }

    EVP_MAC *mac = EVP_MAC_fetch(NULL, name, NULL);
    if (!mac) {
        err->tag = MAC_ERR_UNSUPPORTED;
        return NULL;
    }
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) { err->tag = MAC_ERR_INTERNAL; err->val.internal = 0; return NULL; }

    OSSL_PARAM params[6];
    if (build_mac_params(alg, p, params, 6, err) < 0) {
        EVP_MAC_CTX_free(ctx);
        return NULL;
    }
    if (EVP_MAC_init(ctx, key->ptr, key->len, params) != 1) {
        unsigned long e = ERR_peek_last_error();
        EVP_MAC_CTX_free(ctx);
        // Try to classify common errors.
        err->tag = MAC_ERR_INTERNAL;
        err->val.internal = e;
        return NULL;
    }
    return ctx;
}

// One-shot -----------------------------------------------------------------

bool exports_openssl_component_mac_one_shot(
        exports_openssl_component_mac_algorithm_t alg,
        openssl_list_u8_t *key, openssl_list_u8_t *data,
        exports_openssl_component_mac_params_t *params,
        openssl_list_u8_t *ret,
        exports_openssl_component_mac_mac_error_t *err) {
    EVP_MAC_CTX *ctx = new_mac_ctx(alg, key, params, err);
    if (!ctx) return false;

    if (EVP_MAC_update(ctx, data->ptr, data->len) != 1) {
        EVP_MAC_CTX_free(ctx);
        err->tag = MAC_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }

    // Ask for size, then finalize.
    size_t out_len = 0;
    if (EVP_MAC_final(ctx, NULL, &out_len, 0) != 1) {
        EVP_MAC_CTX_free(ctx);
        err->tag = MAC_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->ptr = xmalloc(out_len ? out_len : 1);
    ret->len = out_len;
    if (EVP_MAC_final(ctx, ret->ptr, &out_len, out_len) != 1) {
        free(ret->ptr);
        EVP_MAC_CTX_free(ctx);
        err->tag = MAC_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->len = out_len;
    EVP_MAC_CTX_free(ctx);
    return true;
}

// Streaming resource -------------------------------------------------------

typedef struct exports_openssl_component_mac_context_t {
    EVP_MAC_CTX *ctx;
} mac_ctx_rep;

exports_openssl_component_mac_own_context_t
exports_openssl_component_mac_constructor_context(
        exports_openssl_component_mac_algorithm_t alg,
        openssl_list_u8_t *key,
        exports_openssl_component_mac_params_t *params) {
    mac_ctx_rep *r = xmalloc(sizeof(*r));
    exports_openssl_component_mac_mac_error_t ignored = {0};
    r->ctx = new_mac_ctx(alg, key, params, &ignored);
    // If init failed, drop the residual queue so it doesn't leak into
    // the caller's next error.drain-errors.
    if (!r->ctx) ERR_clear_error();
    return exports_openssl_component_mac_context_new(r);
}

bool exports_openssl_component_mac_method_context_update(
        exports_openssl_component_mac_borrow_context_t self,
        openssl_list_u8_t *data,
        exports_openssl_component_mac_mac_error_t *err) {
    mac_ctx_rep *r = self;
    if (!r->ctx || EVP_MAC_update(r->ctx, data->ptr, data->len) != 1) {
        err->tag = MAC_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    return true;
}

bool exports_openssl_component_mac_static_context_finish(
        exports_openssl_component_mac_own_context_t handle,
        openssl_list_u8_t *ret,
        exports_openssl_component_mac_mac_error_t *err) {
    mac_ctx_rep *r = exports_openssl_component_mac_context_rep(handle);
    size_t out_len = 0;
    bool ok = r->ctx && EVP_MAC_final(r->ctx, NULL, &out_len, 0) == 1;
    if (ok) {
        ret->ptr = xmalloc(out_len ? out_len : 1);
        ret->len = out_len;
        ok = EVP_MAC_final(r->ctx, ret->ptr, &out_len, out_len) == 1;
        if (ok) ret->len = out_len;
        else free(ret->ptr);
    }
    exports_openssl_component_mac_context_drop_own(handle);
    if (!ok) {
        err->tag = MAC_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    return true;
}

exports_openssl_component_mac_own_context_t
exports_openssl_component_mac_method_context_clone(
        exports_openssl_component_mac_borrow_context_t self) {
    mac_ctx_rep *src = self;
    mac_ctx_rep *dst = xmalloc(sizeof(*dst));
    dst->ctx = src->ctx ? EVP_MAC_CTX_dup(src->ctx) : NULL;
    return exports_openssl_component_mac_context_new(dst);
}

void exports_openssl_component_mac_context_destructor(
        exports_openssl_component_mac_context_t *rep) {
    if (!rep) return;
    if (rep->ctx) EVP_MAC_CTX_free(rep->ctx);
    free(rep);
}
