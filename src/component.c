// WIT → OpenSSL glue.
//
// This file implements the export interfaces that are feasible to get
// right in the first pass: error reporting, randomness, and message
// digests (one-shot + streaming). Every other export is stubbed out by
// scripts/gen-stubs.sh via src/stubs.c.

#include "bindings/openssl.h"
#include "include/support.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// ---------------------------------------------------------------------------
// error
// ---------------------------------------------------------------------------

static void fill_error_info(exports_openssl_component_error_error_info_t *info,
                            unsigned long code,
                            const char *file, int line, const char *data) {
    info->code = code;
    string_take(&info->library, ERR_lib_error_string(code),
                ERR_lib_error_string(code) ? strlen(ERR_lib_error_string(code)) : 0);
    string_take(&info->reason, ERR_reason_error_string(code),
                ERR_reason_error_string(code) ? strlen(ERR_reason_error_string(code)) : 0);
    if (file) {
        info->file.is_some = true;
        string_take(&info->file.val, file, strlen(file));
    } else {
        info->file.is_some = false;
    }
    if (line) {
        info->line.is_some = true;
        info->line.val = (uint32_t)line;
    } else {
        info->line.is_some = false;
    }
    if (data && *data) {
        info->data.is_some = true;
        string_take(&info->data.val, data, strlen(data));
    } else {
        info->data.is_some = false;
    }
}

bool exports_openssl_component_error_pop_error(
        exports_openssl_component_error_error_info_t *ret) {
    const char *file = NULL, *data = NULL;
    int line = 0, flags = 0;
    unsigned long code = ERR_get_error_all(&file, &line, NULL, &data, &flags);
    if (code == 0) return false;
    fill_error_info(ret, code, file, line,
                    (flags & ERR_TXT_STRING) ? data : NULL);
    return true;
}

void exports_openssl_component_error_clear_errors(void) {
    ERR_clear_error();
}

void exports_openssl_component_error_drain_errors(
        exports_openssl_component_error_list_error_info_t *ret) {
    size_t cap = 8, len = 0;
    exports_openssl_component_error_error_info_t *buf =
        xmalloc(cap * sizeof(*buf));
    for (;;) {
        const char *file = NULL, *data = NULL;
        int line = 0, flags = 0;
        unsigned long code = ERR_get_error_all(&file, &line, NULL, &data, &flags);
        if (code == 0) break;
        if (len == cap) {
            cap *= 2;
            buf = realloc(buf, cap * sizeof(*buf));
            if (!buf) abort();
        }
        fill_error_info(&buf[len++], code, file, line,
                        (flags & ERR_TXT_STRING) ? data : NULL);
    }
    ret->ptr = buf;
    ret->len = len;
}

void exports_openssl_component_error_describe(
        exports_openssl_component_error_code_t c, openssl_string_t *ret) {
    char tmp[256];
    ERR_error_string_n((unsigned long)c, tmp, sizeof(tmp));
    string_take(ret, tmp, strlen(tmp));
}

// ---------------------------------------------------------------------------
// random
// ---------------------------------------------------------------------------

bool exports_openssl_component_random_bytes(
        uint32_t n, openssl_list_u8_t *ret,
        exports_openssl_component_random_random_error_t *err) {
    ret->ptr = xmalloc(n ? n : 1);
    ret->len = n;
    if (RAND_bytes(ret->ptr, (int)n) != 1) {
        free(ret->ptr);
        err->tag = EXPORTS_OPENSSL_COMPONENT_RANDOM_RANDOM_ERROR_DRBG_FAILURE;
        err->val.drbg_failure = ERR_peek_last_error();
        return false;
    }
    return true;
}

bool exports_openssl_component_random_private_bytes(
        uint32_t n, openssl_list_u8_t *ret,
        exports_openssl_component_random_random_error_t *err) {
    ret->ptr = xmalloc(n ? n : 1);
    ret->len = n;
    if (RAND_priv_bytes(ret->ptr, (int)n) != 1) {
        free(ret->ptr);
        err->tag = EXPORTS_OPENSSL_COMPONENT_RANDOM_RANDOM_ERROR_DRBG_FAILURE;
        err->val.drbg_failure = ERR_peek_last_error();
        return false;
    }
    return true;
}

void exports_openssl_component_random_add_seed(
        openssl_list_u8_t *material, double entropy_bits) {
    RAND_add(material->ptr, (int)material->len, entropy_bits / 8.0);
}

// ---------------------------------------------------------------------------
// digest (one-shot)
// ---------------------------------------------------------------------------

static const EVP_MD *digest_md(exports_openssl_component_digest_algorithm_t alg) {
    switch (alg) {
    case 0: return EVP_md5();
    case 1: return EVP_sha1();
    case 2: return EVP_sha224();
    case 3: return EVP_sha256();
    case 4: return EVP_sha384();
    case 5: return EVP_sha512();
    case 6: return EVP_sha512_224();
    case 7: return EVP_sha512_256();
    case 8: return EVP_sha3_224();
    case 9: return EVP_sha3_256();
    case 10: return EVP_sha3_384();
    case 11: return EVP_sha3_512();
    case 12: return EVP_shake128();
    case 13: return EVP_shake256();
    case 14: return EVP_blake2s256();
    case 15: return EVP_blake2b512();
    case 16: return EVP_ripemd160();
    case 17: return EVP_sm3();
    default: return NULL;
    }
}

#define DIGEST_ERR_UNSUPPORTED EXPORTS_OPENSSL_COMPONENT_DIGEST_DIGEST_ERROR_UNSUPPORTED_ALGORITHM
#define DIGEST_ERR_XOF         EXPORTS_OPENSSL_COMPONENT_DIGEST_DIGEST_ERROR_XOF_REQUIRED
#define DIGEST_ERR_INTERNAL    EXPORTS_OPENSSL_COMPONENT_DIGEST_DIGEST_ERROR_INTERNAL

static bool digest_is_xof(exports_openssl_component_digest_algorithm_t a) {
    return a == 12 || a == 13;  // shake128, shake256
}

bool exports_openssl_component_digest_one_shot(
        exports_openssl_component_digest_algorithm_t alg,
        openssl_list_u8_t *data, openssl_list_u8_t *ret,
        exports_openssl_component_digest_digest_error_t *err) {
    const EVP_MD *md = digest_md(alg);
    if (!md) { err->tag = DIGEST_ERR_UNSUPPORTED; return false; }
    if (digest_is_xof(alg)) { err->tag = DIGEST_ERR_XOF; return false; }

    unsigned int outlen = (unsigned int)EVP_MD_get_size(md);
    ret->ptr = xmalloc(outlen);
    ret->len = outlen;
    if (EVP_Digest(data->ptr, data->len, ret->ptr, &outlen, md, NULL) != 1) {
        free(ret->ptr);
        err->tag = DIGEST_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->len = outlen;
    return true;
}

bool exports_openssl_component_digest_one_shot_xof(
        exports_openssl_component_digest_algorithm_t alg,
        openssl_list_u8_t *data, uint32_t out_len, openssl_list_u8_t *ret,
        exports_openssl_component_digest_digest_error_t *err) {
    const EVP_MD *md = digest_md(alg);
    if (!md) { err->tag = DIGEST_ERR_UNSUPPORTED; return false; }
    if (!digest_is_xof(alg)) { err->tag = DIGEST_ERR_XOF; return false; }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { err->tag = DIGEST_ERR_INTERNAL; err->val.internal = 0; return false; }

    ret->ptr = xmalloc(out_len ? out_len : 1);
    ret->len = out_len;
    bool ok = EVP_DigestInit_ex(ctx, md, NULL) == 1 &&
              EVP_DigestUpdate(ctx, data->ptr, data->len) == 1 &&
              EVP_DigestFinalXOF(ctx, ret->ptr, out_len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        free(ret->ptr);
        err->tag = DIGEST_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    return true;
}

bool exports_openssl_component_digest_output_size(
        exports_openssl_component_digest_algorithm_t alg, uint32_t *ret,
        exports_openssl_component_digest_digest_error_t *err) {
    const EVP_MD *md = digest_md(alg);
    if (!md) { err->tag = DIGEST_ERR_UNSUPPORTED; return false; }
    *ret = (uint32_t)EVP_MD_get_size(md);
    return true;
}

bool exports_openssl_component_digest_block_size(
        exports_openssl_component_digest_algorithm_t alg, uint32_t *ret,
        exports_openssl_component_digest_digest_error_t *err) {
    const EVP_MD *md = digest_md(alg);
    if (!md) { err->tag = DIGEST_ERR_UNSUPPORTED; return false; }
    *ret = (uint32_t)EVP_MD_get_block_size(md);
    return true;
}

// ---------------------------------------------------------------------------
// digest (streaming resource)
//
// The "rep" for our context resource is a heap-allocated struct that
// carries the EVP_MD_CTX plus the requested algorithm (needed so that
// finish-xof knows whether the alg was a XOF).
// ---------------------------------------------------------------------------

typedef struct exports_openssl_component_digest_context_t {
    EVP_MD_CTX *ctx;
    exports_openssl_component_digest_algorithm_t alg;
} digest_context_rep;

exports_openssl_component_digest_own_context_t
exports_openssl_component_digest_constructor_context(
        exports_openssl_component_digest_algorithm_t alg) {
    digest_context_rep *r = xmalloc(sizeof(*r));
    r->alg = alg;
    r->ctx = EVP_MD_CTX_new();
    const EVP_MD *md = digest_md(alg);
    if (!r->ctx || !md || EVP_DigestInit_ex(r->ctx, md, NULL) != 1) {
        // Record the error on the thread-local queue; caller will see
        // it via exports_openssl_component_error_pop_error. The
        // resource itself is still returned — subsequent update/finish
        // calls will surface INTERNAL.
    }
    return exports_openssl_component_digest_context_new(r);
}

bool exports_openssl_component_digest_method_context_update(
        exports_openssl_component_digest_borrow_context_t self,
        openssl_list_u8_t *data,
        exports_openssl_component_digest_digest_error_t *err) {
    digest_context_rep *r = self;
    if (!r->ctx || EVP_DigestUpdate(r->ctx, data->ptr, data->len) != 1) {
        err->tag = DIGEST_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    return true;
}

bool exports_openssl_component_digest_static_context_finish(
        exports_openssl_component_digest_own_context_t handle,
        openssl_list_u8_t *ret,
        exports_openssl_component_digest_digest_error_t *err) {
    digest_context_rep *r = exports_openssl_component_digest_context_rep(handle);
    if (digest_is_xof(r->alg)) {
        err->tag = DIGEST_ERR_XOF;
        exports_openssl_component_digest_context_drop_own(handle);
        return false;
    }
    unsigned int outlen = (unsigned int)EVP_MD_CTX_get_size(r->ctx);
    ret->ptr = xmalloc(outlen);
    ret->len = outlen;
    bool ok = r->ctx && EVP_DigestFinal_ex(r->ctx, ret->ptr, &outlen) == 1;
    if (ok) ret->len = outlen;
    exports_openssl_component_digest_context_drop_own(handle);
    if (!ok) {
        free(ret->ptr);
        err->tag = DIGEST_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    return true;
}

bool exports_openssl_component_digest_static_context_finish_xof(
        exports_openssl_component_digest_own_context_t handle,
        uint32_t out_len, openssl_list_u8_t *ret,
        exports_openssl_component_digest_digest_error_t *err) {
    digest_context_rep *r = exports_openssl_component_digest_context_rep(handle);
    if (!digest_is_xof(r->alg)) {
        err->tag = DIGEST_ERR_XOF;
        exports_openssl_component_digest_context_drop_own(handle);
        return false;
    }
    ret->ptr = xmalloc(out_len ? out_len : 1);
    ret->len = out_len;
    bool ok = r->ctx && EVP_DigestFinalXOF(r->ctx, ret->ptr, out_len) == 1;
    exports_openssl_component_digest_context_drop_own(handle);
    if (!ok) {
        free(ret->ptr);
        err->tag = DIGEST_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    return true;
}

exports_openssl_component_digest_own_context_t
exports_openssl_component_digest_method_context_clone(
        exports_openssl_component_digest_borrow_context_t self) {
    digest_context_rep *src = self;
    digest_context_rep *dst = xmalloc(sizeof(*dst));
    dst->alg = src->alg;
    dst->ctx = EVP_MD_CTX_new();
    if (dst->ctx && src->ctx) {
        EVP_MD_CTX_copy_ex(dst->ctx, src->ctx);
    }
    return exports_openssl_component_digest_context_new(dst);
}

void exports_openssl_component_digest_context_destructor(
        exports_openssl_component_digest_context_t *rep) {
    if (!rep) return;
    if (rep->ctx) EVP_MD_CTX_free(rep->ctx);
    free(rep);
}
