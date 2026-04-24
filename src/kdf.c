// kdf interface — EVP_KDF.
//
// Each WIT function maps to a named EVP_KDF and a small OSSL_PARAM array.

#include "bindings/openssl.h"
#include "include/support.h"
#include "include/algs.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#define KDF_ERR_UNSUPPORTED EXPORTS_OPENSSL_COMPONENT_KDF_KDF_ERROR_UNSUPPORTED_ALGORITHM
#define KDF_ERR_INVALID     EXPORTS_OPENSSL_COMPONENT_KDF_KDF_ERROR_INVALID_PARAMETER
#define KDF_ERR_TOO_LARGE   EXPORTS_OPENSSL_COMPONENT_KDF_KDF_ERROR_OUTPUT_TOO_LARGE
#define KDF_ERR_INTERNAL    EXPORTS_OPENSSL_COMPONENT_KDF_KDF_ERROR_INTERNAL

static bool derive(const char *name,
                   const OSSL_PARAM *params,
                   uint32_t out_len,
                   openssl_list_u8_t *ret,
                   exports_openssl_component_kdf_kdf_error_t *err) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, name, NULL);
    if (!kdf) { err->tag = KDF_ERR_UNSUPPORTED; return false; }
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) { err->tag = KDF_ERR_INTERNAL; err->val.internal = 0; return false; }

    ret->ptr = xmalloc(out_len ? out_len : 1);
    ret->len = out_len;

    int rc = EVP_KDF_derive(ctx, ret->ptr, out_len, params);
    EVP_KDF_CTX_free(ctx);
    if (rc != 1) {
        free(ret->ptr);
        err->tag = KDF_ERR_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    return true;
}

// PBKDF2 -------------------------------------------------------------------

bool exports_openssl_component_kdf_pbkdf2(
        openssl_list_u8_t *password,
        exports_openssl_component_kdf_pbkdf2_params_t *params,
        uint32_t out_len, openssl_list_u8_t *ret,
        exports_openssl_component_kdf_kdf_error_t *err) {
    const char *dname = wit_digest_name(params->hash);
    if (!dname) { err->tag = KDF_ERR_UNSUPPORTED; return false; }
    unsigned int iter = params->iterations;
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                          password->ptr, password->len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                          params->salt.ptr, params->salt.len),
        OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                         (char *)dname, 0),
        OSSL_PARAM_construct_end()
    };
    return derive("PBKDF2", p, out_len, ret, err);
}

// HKDF (extract+expand) ----------------------------------------------------

bool exports_openssl_component_kdf_hkdf(
        openssl_list_u8_t *ikm,
        exports_openssl_component_kdf_hkdf_params_t *params,
        uint32_t out_len, openssl_list_u8_t *ret,
        exports_openssl_component_kdf_kdf_error_t *err) {
    const char *dname = wit_digest_name(params->hash);
    if (!dname) { err->tag = KDF_ERR_UNSUPPORTED; return false; }

    OSSL_PARAM p[6];
    size_t i = 0;
    p[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                              (char *)dname, 0);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                              ikm->ptr, ikm->len);
    if (params->salt.is_some) {
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                   params->salt.val.ptr,
                                                   params->salt.val.len);
    }
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                               params->info.ptr, params->info.len);
    p[i] = OSSL_PARAM_construct_end();
    return derive("HKDF", p, out_len, ret, err);
}

bool exports_openssl_component_kdf_hkdf_extract(
        openssl_list_u8_t *ikm,
        exports_openssl_component_kdf_hkdf_extract_params_t *params,
        openssl_list_u8_t *ret,
        exports_openssl_component_kdf_kdf_error_t *err) {
    const char *dname = wit_digest_name(params->hash);
    if (!dname) { err->tag = KDF_ERR_UNSUPPORTED; return false; }
    const EVP_MD *md = wit_digest_md(params->hash);
    uint32_t hlen = md ? (uint32_t)EVP_MD_get_size(md) : 0;
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    OSSL_PARAM p[6];
    size_t i = 0;
    p[i++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    p[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                              (char *)dname, 0);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                              ikm->ptr, ikm->len);
    if (params->salt.is_some) {
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                   params->salt.val.ptr,
                                                   params->salt.val.len);
    }
    p[i] = OSSL_PARAM_construct_end();
    return derive("HKDF", p, hlen, ret, err);
}

bool exports_openssl_component_kdf_hkdf_expand(
        openssl_list_u8_t *prk,
        exports_openssl_component_kdf_hkdf_expand_params_t *params,
        uint32_t out_len, openssl_list_u8_t *ret,
        exports_openssl_component_kdf_kdf_error_t *err) {
    const char *dname = wit_digest_name(params->hash);
    if (!dname) { err->tag = KDF_ERR_UNSUPPORTED; return false; }
    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)dname, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, prk->ptr, prk->len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          params->info.ptr, params->info.len),
        OSSL_PARAM_construct_end()
    };
    return derive("HKDF", p, out_len, ret, err);
}

// scrypt -------------------------------------------------------------------

bool exports_openssl_component_kdf_scrypt(
        openssl_list_u8_t *password,
        exports_openssl_component_kdf_scrypt_params_t *params,
        uint32_t out_len, openssl_list_u8_t *ret,
        exports_openssl_component_kdf_kdf_error_t *err) {
    uint64_t n = params->n;
    uint32_t r = params->r, pp = params->p;
    uint64_t max_mem = params->max_mem;
    OSSL_PARAM p[8];
    size_t i = 0;
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                               password->ptr, password->len);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                               params->salt.ptr, params->salt.len);
    p[i++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n);
    p[i++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r);
    p[i++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &pp);
    if (max_mem) {
        p[i++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &max_mem);
    }
    p[i] = OSSL_PARAM_construct_end();
    return derive("SCRYPT", p, out_len, ret, err);
}

// Argon2 -------------------------------------------------------------------

bool exports_openssl_component_kdf_argon2(
        openssl_list_u8_t *password,
        exports_openssl_component_kdf_argon2_params_t *params,
        uint32_t out_len, openssl_list_u8_t *ret,
        exports_openssl_component_kdf_kdf_error_t *err) {
    const char *name;
    switch (params->kind) {
    case 0: name = "ARGON2D";  break;
    case 1: name = "ARGON2I";  break;
    case 2: name = "ARGON2ID"; break;
    default: err->tag = KDF_ERR_UNSUPPORTED; return false;
    }
    uint32_t lanes = params->lanes;
    uint32_t mcost = params->m_cost;
    uint32_t tcost = params->t_cost;
    OSSL_PARAM p[10];
    size_t i = 0;
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                               password->ptr, password->len);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                               params->salt.ptr, params->salt.len);
    if (params->secret.is_some) {
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
                                                   params->secret.val.ptr,
                                                   params->secret.val.len);
    }
    if (params->ad.is_some) {
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_ARGON2_AD,
                                                   params->ad.val.ptr,
                                                   params->ad.val.len);
    }
    p[i++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    p[i++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mcost);
    p[i++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &tcost);
    p[i] = OSSL_PARAM_construct_end();
    return derive(name, p, out_len, ret, err);
}

// KBKDF (SP 800-108 HMAC counter mode) -------------------------------------

bool exports_openssl_component_kdf_kbkdf(
        openssl_list_u8_t *key,
        exports_openssl_component_kdf_kbkdf_params_t *params,
        uint32_t out_len, openssl_list_u8_t *ret,
        exports_openssl_component_kdf_kdf_error_t *err) {
    const char *dname = wit_digest_name(params->hash);
    if (!dname) { err->tag = KDF_ERR_UNSUPPORTED; return false; }
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "HMAC", 0),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)dname, 0),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "COUNTER", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key->ptr, key->len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                          params->label.ptr, params->label.len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          params->context.ptr, params->context.len),
        OSSL_PARAM_construct_end()
    };
    return derive("KBKDF", p, out_len, ret, err);
}

// SP 800-56A concat (single-step) ------------------------------------------

bool exports_openssl_component_kdf_ss_kdf(
        openssl_list_u8_t *shared_secret,
        exports_openssl_component_kdf_ss_kdf_params_t *params,
        uint32_t out_len, openssl_list_u8_t *ret,
        exports_openssl_component_kdf_kdf_error_t *err) {
    const char *dname = wit_digest_name(params->hash);
    if (!dname) { err->tag = KDF_ERR_UNSUPPORTED; return false; }
    OSSL_PARAM p[6];
    size_t i = 0;
    p[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                              (char *)dname, 0);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                               shared_secret->ptr,
                                               shared_secret->len);
    p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                               params->info.ptr, params->info.len);
    if (params->salt.is_some) {
        p[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                   params->salt.val.ptr,
                                                   params->salt.val.len);
    }
    p[i] = OSSL_PARAM_construct_end();
    return derive("SSKDF", p, out_len, ret, err);
}

// ANSI X9.63 ---------------------------------------------------------------

bool exports_openssl_component_kdf_x963_kdf(
        openssl_list_u8_t *shared_secret,
        exports_openssl_component_kdf_x963_kdf_params_t *params,
        uint32_t out_len, openssl_list_u8_t *ret,
        exports_openssl_component_kdf_kdf_error_t *err) {
    const char *dname = wit_digest_name(params->hash);
    if (!dname) { err->tag = KDF_ERR_UNSUPPORTED; return false; }
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)dname, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                          shared_secret->ptr, shared_secret->len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          params->info.ptr, params->info.len),
        OSSL_PARAM_construct_end()
    };
    return derive("X963KDF", p, out_len, ret, err);
}

// TLS 1.3 HKDF-Expand-Label ------------------------------------------------

bool exports_openssl_component_kdf_tls13_expand_label(
        exports_openssl_component_kdf_tls13_expand_label_params_t *params,
        uint32_t out_len, openssl_list_u8_t *ret,
        exports_openssl_component_kdf_kdf_error_t *err) {
    const char *dname = wit_digest_name(params->hash);
    if (!dname) { err->tag = KDF_ERR_UNSUPPORTED; return false; }
    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    // Build HkdfLabel per RFC 8446 §7.1: length(2) || "tls13 " || label ||
    // context_length(1) || context.
    const char *prefix = "tls13 ";
    size_t prefix_len = 6;
    if (params->label.len + prefix_len > 255 ||
        params->context.len > 255 ||
        out_len > 65535) {
        err->tag = KDF_ERR_INVALID;
        return false;
    }
    size_t info_len = 2 + 1 + prefix_len + params->label.len
                    + 1 + params->context.len;
    unsigned char *info = xmalloc(info_len);
    size_t o = 0;
    info[o++] = (out_len >> 8) & 0xff;
    info[o++] = out_len & 0xff;
    info[o++] = (unsigned char)(prefix_len + params->label.len);
    memcpy(info + o, prefix, prefix_len); o += prefix_len;
    memcpy(info + o, params->label.ptr, params->label.len);
    o += params->label.len;
    info[o++] = (unsigned char)params->context.len;
    memcpy(info + o, params->context.ptr, params->context.len);
    o += params->context.len;

    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)dname, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                          params->secret.ptr, params->secret.len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, info_len),
        OSSL_PARAM_construct_end()
    };
    bool r = derive("HKDF", p, out_len, ret, err);
    free(info);
    return r;
}
