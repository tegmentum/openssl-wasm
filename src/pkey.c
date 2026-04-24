// pkey interface — EVP_PKEY: keygen, sign/verify, encrypt/decrypt, derive.

#include "bindings/openssl.h"
#include "include/support.h"
#include "include/algs.h"

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define PE_UNSUPPORTED_TYPE  EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_UNSUPPORTED_TYPE
#define PE_BAD_ENCODING      EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_BAD_ENCODING
#define PE_BAD_PASSPHRASE    EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_BAD_PASSPHRASE
#define PE_UNSUPPORTED_CURVE EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_UNSUPPORTED_CURVE
#define PE_INVALID_SIG       EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_INVALID_SIGNATURE
#define PE_BAD_KEY_SIZE      EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_BAD_KEY_SIZE
#define PE_DECRYPT_FAILED    EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_DECRYPT_FAILED
#define PE_ENCRYPT_FAILED    EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_ENCRYPT_FAILED
#define PE_SIGN_FAILED       EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_SIGN_FAILED
#define PE_VERIFY_FAILED     EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_VERIFY_FAILED
#define PE_DERIVE_FAILED     EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_DERIVE_FAILED
#define PE_KEYGEN_FAILED     EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_KEYGEN_FAILED
#define PE_INTERNAL          EXPORTS_OPENSSL_COMPONENT_PKEY_PKEY_ERROR_INTERNAL

#define KEYGEN_RSA     EXPORTS_OPENSSL_COMPONENT_PKEY_KEYGEN_PARAMS_RSA
#define KEYGEN_RSA_PSS EXPORTS_OPENSSL_COMPONENT_PKEY_KEYGEN_PARAMS_RSA_PSS
#define KEYGEN_EC      EXPORTS_OPENSSL_COMPONENT_PKEY_KEYGEN_PARAMS_EC
#define KEYGEN_ED      EXPORTS_OPENSSL_COMPONENT_PKEY_KEYGEN_PARAMS_ED
#define KEYGEN_X       EXPORTS_OPENSSL_COMPONENT_PKEY_KEYGEN_PARAMS_X
#define KEYGEN_DH      EXPORTS_OPENSSL_COMPONENT_PKEY_KEYGEN_PARAMS_DH

#define PAD_PKCS1      EXPORTS_OPENSSL_COMPONENT_PKEY_RSA_PADDING_PKCS1
#define PAD_OAEP       EXPORTS_OPENSSL_COMPONENT_PKEY_RSA_PADDING_PKCS1_OAEP
#define PAD_PSS        EXPORTS_OPENSSL_COMPONENT_PKEY_RSA_PADDING_PKCS1_PSS
#define PAD_NONE       EXPORTS_OPENSSL_COMPONENT_PKEY_RSA_PADDING_NO_PADDING

#define KT_RSA     EXPORTS_OPENSSL_COMPONENT_PKEY_KEY_TYPE_RSA
#define KT_RSA_PSS EXPORTS_OPENSSL_COMPONENT_PKEY_KEY_TYPE_RSA_PSS
#define KT_EC      EXPORTS_OPENSSL_COMPONENT_PKEY_KEY_TYPE_EC
#define KT_ED      EXPORTS_OPENSSL_COMPONENT_PKEY_KEY_TYPE_ED
#define KT_X       EXPORTS_OPENSSL_COMPONENT_PKEY_KEY_TYPE_X
#define KT_DH      EXPORTS_OPENSSL_COMPONENT_PKEY_KEY_TYPE_DH

#define ENC_PEM 0
#define ENC_DER 1
#define FMT_TRADITIONAL 0
#define FMT_PKCS8 1
#define FMT_SPKI 2

static const char *curve_name(exports_openssl_component_pkey_curve_t c) {
    switch (c) {
    case 0: return "P-192";
    case 1: return "P-224";
    case 2: return "P-256";
    case 3: return "P-384";
    case 4: return "P-521";
    case 5: return "secp256k1";
    case 6: return "brainpoolP256r1";
    case 7: return "brainpoolP384r1";
    case 8: return "brainpoolP512r1";
    case 9: return "SM2";
    default: return NULL;
    }
}

static const char *edwards_name(exports_openssl_component_pkey_edwards_curve_t c) {
    return c == 0 ? "ED25519" : (c == 1 ? "ED448" : NULL);
}

static const char *montgomery_name(exports_openssl_component_pkey_montgomery_curve_t c) {
    return c == 0 ? "X25519" : (c == 1 ? "X448" : NULL);
}

static inline EVP_PKEY *as_pkey(exports_openssl_component_pkey_borrow_pkey_t b) {
    return (EVP_PKEY *)b;
}
static inline EVP_PKEY *as_pkey_rep(exports_openssl_component_pkey_pkey_t *r) {
    return (EVP_PKEY *)r;
}
static exports_openssl_component_pkey_own_pkey_t handle_of(EVP_PKEY *p) {
    return exports_openssl_component_pkey_pkey_new(
        (exports_openssl_component_pkey_pkey_t *)p);
}

// Keygen -------------------------------------------------------------------

bool exports_openssl_component_pkey_static_pkey_generate(
        exports_openssl_component_pkey_keygen_params_t *params,
        exports_openssl_component_pkey_own_pkey_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    switch (params->tag) {
    case KEYGEN_RSA:
    case KEYGEN_RSA_PSS: {
        const char *name = params->tag == KEYGEN_RSA ? "RSA" : "RSA-PSS";
        ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) goto fail;
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)params->val.rsa.bits) <= 0) {
            err->tag = PE_BAD_KEY_SIZE; goto cleanup;
        }
        if (params->val.rsa.public_exponent.is_some) {
            BIGNUM *e = BN_new();
            BN_set_word(e, params->val.rsa.public_exponent.val);
            if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) <= 0) {
                BN_free(e);
                err->tag = PE_BAD_KEY_SIZE; goto cleanup;
            }
        }
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto fail;
        break;
    }
    case KEYGEN_EC: {
        const char *curve = curve_name(params->val.ec);
        if (!curve) { err->tag = PE_UNSUPPORTED_CURVE; return false; }
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) goto fail;
        OSSL_PARAM p[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                             (char *)curve, 0),
            OSSL_PARAM_construct_end()
        };
        if (EVP_PKEY_CTX_set_params(ctx, p) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) goto fail;
        break;
    }
    case KEYGEN_ED: {
        const char *name = edwards_name(params->val.ed);
        if (!name) { err->tag = PE_UNSUPPORTED_CURVE; return false; }
        ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) goto fail;
        break;
    }
    case KEYGEN_X: {
        const char *name = montgomery_name(params->val.x);
        if (!name) { err->tag = PE_UNSUPPORTED_CURVE; return false; }
        ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) goto fail;
        break;
    }
    case KEYGEN_DH: {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        if (!ctx || EVP_PKEY_paramgen_init(ctx) <= 0) goto fail;
        uint32_t bits = params->val.dh.prime_bits;
        uint32_t g = params->val.dh.generator;
        OSSL_PARAM p[] = {
            OSSL_PARAM_construct_uint32("pbits", &bits),
            OSSL_PARAM_construct_uint32("generator", &g),
            OSSL_PARAM_construct_end()
        };
        EVP_PKEY *pparams = NULL;
        EVP_PKEY_CTX_set_params(ctx, p);
        if (EVP_PKEY_paramgen(ctx, &pparams) <= 0) goto fail;
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pparams, NULL);
        EVP_PKEY_free(pparams);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) goto fail;
        break;
    }
    default:
        err->tag = PE_UNSUPPORTED_TYPE;
        return false;
    }
    EVP_PKEY_CTX_free(ctx);
    *ret = handle_of(pkey);
    return true;

fail:
    err->tag = PE_KEYGEN_FAILED;
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    err->val.internal = ERR_peek_last_error();
    return false;
}

// Encoding helpers ---------------------------------------------------------

static int pw_cb(char *buf, int size, int rwflag, void *userdata) {
    (void)rwflag;
    const openssl_option_list_u8_t *pw = userdata;
    if (!pw || !pw->is_some) return 0;
    int n = (int)pw->val.len;
    if (n > size) n = size;
    memcpy(buf, pw->val.ptr, n);
    return n;
}

static bool load_key_from_bytes(
        const openssl_list_u8_t *bytes,
        const exports_openssl_component_pkey_load_options_t *opts,
        int want_private,
        exports_openssl_component_pkey_own_pkey_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    BIO *bio = BIO_new_mem_buf(bytes->ptr, (int)bytes->len);
    if (!bio) { err->tag = PE_INTERNAL; err->val.internal = 0; return false; }

    EVP_PKEY *pkey = NULL;
    const char *fmt_str = opts->encoding == ENC_PEM ? "PEM" : "DER";
    // Map format→structure so OSSL_DECODER picks the right parser.
    // NULL means "any"; we only pass a specific structure when we know.
    const char *structure = NULL;
    if (want_private) {
        if      (opts->format == FMT_PKCS8)       structure = "PrivateKeyInfo";
        else if (opts->format == FMT_TRADITIONAL) structure = "type-specific";
    } else {
        if (opts->format == FMT_SPKI)             structure = "SubjectPublicKeyInfo";
    }
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(
        &pkey, fmt_str, structure, NULL,
        want_private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
        NULL, NULL);
    if (!dctx) { BIO_free(bio); err->tag = PE_INTERNAL; err->val.internal = 0; return false; }
    if (opts->passphrase.is_some) {
        OSSL_DECODER_CTX_set_pem_password_cb(dctx, pw_cb,
            (void *)&opts->passphrase);
    }
    int ok = OSSL_DECODER_from_bio(dctx, bio);
    OSSL_DECODER_CTX_free(dctx);
    BIO_free(bio);
    if (!ok || !pkey) {
        if (pkey) EVP_PKEY_free(pkey);
        err->tag = PE_BAD_ENCODING;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    *ret = handle_of(pkey);
    return true;
}

bool exports_openssl_component_pkey_static_pkey_load_private(
        openssl_list_u8_t *bytes,
        exports_openssl_component_pkey_load_options_t *opts,
        exports_openssl_component_pkey_own_pkey_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    return load_key_from_bytes(bytes, opts, 1, ret, err);
}

bool exports_openssl_component_pkey_static_pkey_load_public(
        openssl_list_u8_t *bytes,
        exports_openssl_component_pkey_load_options_t *opts,
        exports_openssl_component_pkey_own_pkey_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    return load_key_from_bytes(bytes, opts, 0, ret, err);
}

bool exports_openssl_component_pkey_static_pkey_from_raw_private(
        exports_openssl_component_pkey_key_type_t *kind,
        openssl_list_u8_t *bytes,
        exports_openssl_component_pkey_own_pkey_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    const char *name = NULL;
    if (kind->tag == KT_ED) name = edwards_name(kind->val.ed);
    else if (kind->tag == KT_X) name = montgomery_name(kind->val.x);
    if (!name) { err->tag = PE_UNSUPPORTED_TYPE; return false; }
    EVP_PKEY *p = EVP_PKEY_new_raw_private_key_ex(NULL, name, NULL,
                                                   bytes->ptr, bytes->len);
    if (!p) { err->tag = PE_BAD_ENCODING; err->val.internal = ERR_peek_last_error(); return false; }
    *ret = handle_of(p);
    return true;
}

bool exports_openssl_component_pkey_static_pkey_from_raw_public(
        exports_openssl_component_pkey_key_type_t *kind,
        openssl_list_u8_t *bytes,
        exports_openssl_component_pkey_own_pkey_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    const char *name = NULL;
    if (kind->tag == KT_ED) name = edwards_name(kind->val.ed);
    else if (kind->tag == KT_X) name = montgomery_name(kind->val.x);
    if (!name) { err->tag = PE_UNSUPPORTED_TYPE; return false; }
    EVP_PKEY *p = EVP_PKEY_new_raw_public_key_ex(NULL, name, NULL,
                                                  bytes->ptr, bytes->len);
    if (!p) { err->tag = PE_BAD_ENCODING; err->val.internal = ERR_peek_last_error(); return false; }
    *ret = handle_of(p);
    return true;
}

// Metadata -----------------------------------------------------------------

void exports_openssl_component_pkey_method_pkey_kind(
        exports_openssl_component_pkey_borrow_pkey_t self,
        exports_openssl_component_pkey_key_type_t *ret) {
    EVP_PKEY *p = as_pkey(self);
    int id = EVP_PKEY_get_base_id(p);
    memset(ret, 0, sizeof(*ret));
    switch (id) {
    case EVP_PKEY_RSA:     ret->tag = KT_RSA; break;
    case EVP_PKEY_RSA_PSS: ret->tag = KT_RSA_PSS; break;
    case EVP_PKEY_EC: {
        ret->tag = KT_EC;
        // Default to P-256 if the group name is unavailable.
        ret->val.ec = 2;
        // Try the modern fetch-by-nid path first, then fall back to the
        // OSSL_PARAM string. Either one works; both fail for some providers.
        char grp[80] = {0};
        size_t glen = 0;
        int got = EVP_PKEY_get_group_name(p, grp, sizeof(grp), &glen);
        if (got != 1) {
            got = EVP_PKEY_get_utf8_string_param(p, OSSL_PKEY_PARAM_GROUP_NAME,
                                                  grp, sizeof(grp), &glen);
        }
        if (got == 1) {
            if      (!strcmp(grp, "P-192") || !strcmp(grp, "prime192v1") ||
                     !strcmp(grp, "secp192r1")) ret->val.ec = 0;
            else if (!strcmp(grp, "P-224") || !strcmp(grp, "secp224r1")) ret->val.ec = 1;
            else if (!strcmp(grp, "P-256") || !strcmp(grp, "prime256v1") ||
                     !strcmp(grp, "secp256r1")) ret->val.ec = 2;
            else if (!strcmp(grp, "P-384") || !strcmp(grp, "secp384r1")) ret->val.ec = 3;
            else if (!strcmp(grp, "P-521") || !strcmp(grp, "secp521r1")) ret->val.ec = 4;
            else if (!strcmp(grp, "secp256k1")) ret->val.ec = 5;
            else if (!strcmp(grp, "brainpoolP256r1")) ret->val.ec = 6;
            else if (!strcmp(grp, "brainpoolP384r1")) ret->val.ec = 7;
            else if (!strcmp(grp, "brainpoolP512r1")) ret->val.ec = 8;
            else if (!strcmp(grp, "SM2")) ret->val.ec = 9;
        }
        break;
    }
    case EVP_PKEY_ED25519: ret->tag = KT_ED; ret->val.ed = 0; break;
    case EVP_PKEY_ED448:   ret->tag = KT_ED; ret->val.ed = 1; break;
    case EVP_PKEY_X25519:  ret->tag = KT_X;  ret->val.x = 0; break;
    case EVP_PKEY_X448:    ret->tag = KT_X;  ret->val.x = 1; break;
    case EVP_PKEY_DH:      ret->tag = KT_DH; break;
    default:               ret->tag = KT_RSA; break;
    }
}

uint32_t exports_openssl_component_pkey_method_pkey_bits(
        exports_openssl_component_pkey_borrow_pkey_t self) {
    return (uint32_t)EVP_PKEY_get_bits(as_pkey(self));
}

uint32_t exports_openssl_component_pkey_method_pkey_security_bits(
        exports_openssl_component_pkey_borrow_pkey_t self) {
    return (uint32_t)EVP_PKEY_get_security_bits(as_pkey(self));
}

bool exports_openssl_component_pkey_method_pkey_has_private(
        exports_openssl_component_pkey_borrow_pkey_t self) {
    // Probe: try to extract a private key component. Accept any OK-ish
    // response. Each failed probe pushes errors to the thread-local
    // queue; we clear them before returning so subsequent error::drain
    // calls don't see probe noise.
    EVP_PKEY *p = as_pkey(self);
    size_t n = 0;
    bool found = false;
    if (EVP_PKEY_get_raw_private_key(p, NULL, &n) == 1) {
        found = true;
    } else {
        BIGNUM *bn = NULL;
        if (EVP_PKEY_get_bn_param(p, OSSL_PKEY_PARAM_PRIV_KEY, &bn) == 1) {
            found = true;
        } else if (EVP_PKEY_get_bn_param(p, OSSL_PKEY_PARAM_RSA_D, &bn) == 1) {
            found = true;
        }
        if (bn) BN_free(bn);
    }
    ERR_clear_error();
    return found;
}

// Save / raw ---------------------------------------------------------------

static bool encode_key(EVP_PKEY *p,
                       const exports_openssl_component_pkey_save_options_t *opts,
                       int want_private,
                       openssl_list_u8_t *ret,
                       exports_openssl_component_pkey_pkey_error_t *err) {
    const char *fmt_str = opts->encoding == ENC_PEM ? "PEM" : "DER";
    int selection;
    const char *structure;
    if (want_private) {
        selection = EVP_PKEY_KEYPAIR;
        structure = opts->format == FMT_PKCS8 ? "PrivateKeyInfo"
                  : (opts->format == FMT_SPKI ? "SubjectPublicKeyInfo"
                                              : "type-specific");
    } else {
        selection = EVP_PKEY_PUBLIC_KEY;
        structure = "SubjectPublicKeyInfo";
    }
    OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(
        p, selection, fmt_str, structure, NULL);
    if (!ectx) { err->tag = PE_INTERNAL; err->val.internal = 0; return false; }
    if (want_private && opts->passphrase.is_some && opts->format == FMT_PKCS8) {
        OSSL_ENCODER_CTX_set_passphrase(ectx,
            opts->passphrase.val.ptr, opts->passphrase.val.len);
        OSSL_ENCODER_CTX_set_cipher(ectx, "AES-256-CBC", NULL);
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) { OSSL_ENCODER_CTX_free(ectx); err->tag = PE_INTERNAL; err->val.internal = 0; return false; }
    int ok = OSSL_ENCODER_to_bio(ectx, bio);
    OSSL_ENCODER_CTX_free(ectx);
    if (!ok) {
        BIO_free(bio);
        err->tag = PE_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    const unsigned char *buf = NULL;
    long buflen = BIO_get_mem_data(bio, &buf);
    ret->ptr = xmalloc(buflen > 0 ? (size_t)buflen : 1);
    memcpy(ret->ptr, buf, buflen);
    ret->len = (size_t)buflen;
    BIO_free(bio);
    return true;
}

bool exports_openssl_component_pkey_method_pkey_save_private(
        exports_openssl_component_pkey_borrow_pkey_t self,
        exports_openssl_component_pkey_save_options_t *opts,
        openssl_list_u8_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    return encode_key(as_pkey(self), opts, 1, ret, err);
}

bool exports_openssl_component_pkey_method_pkey_save_public(
        exports_openssl_component_pkey_borrow_pkey_t self,
        exports_openssl_component_pkey_save_options_t *opts,
        openssl_list_u8_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    return encode_key(as_pkey(self), opts, 0, ret, err);
}

bool exports_openssl_component_pkey_method_pkey_raw_private(
        exports_openssl_component_pkey_borrow_pkey_t self,
        openssl_list_u8_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    EVP_PKEY *p = as_pkey(self);
    size_t n = 0;
    if (EVP_PKEY_get_raw_private_key(p, NULL, &n) != 1) {
        err->tag = PE_UNSUPPORTED_TYPE; return false;
    }
    ret->ptr = xmalloc(n ? n : 1);
    ret->len = n;
    if (EVP_PKEY_get_raw_private_key(p, ret->ptr, &n) != 1) {
        free(ret->ptr);
        err->tag = PE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->len = n;
    return true;
}

bool exports_openssl_component_pkey_method_pkey_raw_public(
        exports_openssl_component_pkey_borrow_pkey_t self,
        openssl_list_u8_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    EVP_PKEY *p = as_pkey(self);
    size_t n = 0;
    if (EVP_PKEY_get_raw_public_key(p, NULL, &n) != 1) {
        err->tag = PE_UNSUPPORTED_TYPE; return false;
    }
    ret->ptr = xmalloc(n ? n : 1);
    ret->len = n;
    if (EVP_PKEY_get_raw_public_key(p, ret->ptr, &n) != 1) {
        free(ret->ptr);
        err->tag = PE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->len = n;
    return true;
}

// RSA padding setter for sign/verify/encrypt/decrypt contexts --------------

static bool apply_rsa_padding(EVP_PKEY_CTX *ctx,
                              const exports_openssl_component_pkey_rsa_padding_t *pad,
                              int is_sig) {
    if (!pad) return true;
    switch (pad->tag) {
    case PAD_PKCS1:
        return EVP_PKEY_CTX_set_rsa_padding(ctx, is_sig ? RSA_PKCS1_PADDING : RSA_PKCS1_PADDING) > 0;
    case PAD_NONE:
        return EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) > 0;
    case PAD_OAEP: {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return false;
        const EVP_MD *md = wit_digest_md(pad->val.pkcs1_oaep.hash);
        const EVP_MD *mgf = wit_digest_md(pad->val.pkcs1_oaep.mgf1_hash);
        if (!md || !mgf) return false;
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) return false;
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf) <= 0) return false;
        const openssl_list_u8_t *lbl = &pad->val.pkcs1_oaep.label;
        if (lbl->len) {
            unsigned char *copy = OPENSSL_memdup(lbl->ptr, lbl->len);
            if (!copy) return false;
            if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, copy, (int)lbl->len) <= 0) {
                OPENSSL_free(copy);
                return false;
            }
        }
        return true;
    }
    case PAD_PSS: {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) return false;
        const EVP_MD *mgf = wit_digest_md(pad->val.pkcs1_pss.mgf1_hash);
        if (!mgf) return false;
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf) <= 0) return false;
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, pad->val.pkcs1_pss.salt_len) <= 0) return false;
        return true;
    }
    default:
        return false;
    }
}

// Sign / verify ------------------------------------------------------------

bool exports_openssl_component_pkey_method_pkey_sign_digest(
        exports_openssl_component_pkey_borrow_pkey_t self,
        exports_openssl_component_pkey_hash_t hash,
        openssl_list_u8_t *digest,
        exports_openssl_component_pkey_rsa_padding_t *maybe_padding,
        openssl_list_u8_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    EVP_PKEY *p = as_pkey(self);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(p, NULL);
    if (!ctx || EVP_PKEY_sign_init(ctx) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        err->tag = PE_SIGN_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    const EVP_MD *md = wit_digest_md(hash);
    if (!md) { EVP_PKEY_CTX_free(ctx); err->tag = PE_UNSUPPORTED_TYPE; return false; }
    if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0 ||
        !apply_rsa_padding(ctx, maybe_padding, 1)) {
        EVP_PKEY_CTX_free(ctx);
        err->tag = PE_SIGN_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    size_t siglen = 0;
    if (EVP_PKEY_sign(ctx, NULL, &siglen, digest->ptr, digest->len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        err->tag = PE_SIGN_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->ptr = xmalloc(siglen ? siglen : 1);
    ret->len = siglen;
    if (EVP_PKEY_sign(ctx, ret->ptr, &siglen, digest->ptr, digest->len) <= 0) {
        free(ret->ptr);
        EVP_PKEY_CTX_free(ctx);
        err->tag = PE_SIGN_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->len = siglen;
    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool exports_openssl_component_pkey_method_pkey_sign_message(
        exports_openssl_component_pkey_borrow_pkey_t self,
        exports_openssl_component_pkey_hash_t *maybe_hash,
        openssl_list_u8_t *message,
        exports_openssl_component_pkey_rsa_padding_t *maybe_padding,
        openssl_list_u8_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    EVP_PKEY *p = as_pkey(self);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { err->tag = PE_INTERNAL; err->val.internal = 0; return false; }

    const EVP_MD *md = NULL;
    if (maybe_hash) {
        md = wit_digest_md(*maybe_hash);
        if (!md) { EVP_MD_CTX_free(mctx); err->tag = PE_UNSUPPORTED_TYPE; return false; }
    }

    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestSignInit(mctx, &pctx, md, NULL, p) <= 0) {
        EVP_MD_CTX_free(mctx);
        err->tag = PE_SIGN_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    if (!apply_rsa_padding(pctx, maybe_padding, 1)) {
        EVP_MD_CTX_free(mctx);
        err->tag = PE_SIGN_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    size_t siglen = 0;
    if (EVP_DigestSign(mctx, NULL, &siglen, message->ptr, message->len) <= 0) {
        EVP_MD_CTX_free(mctx);
        err->tag = PE_SIGN_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->ptr = xmalloc(siglen ? siglen : 1);
    ret->len = siglen;
    if (EVP_DigestSign(mctx, ret->ptr, &siglen, message->ptr, message->len) <= 0) {
        free(ret->ptr);
        EVP_MD_CTX_free(mctx);
        err->tag = PE_SIGN_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->len = siglen;
    EVP_MD_CTX_free(mctx);
    return true;
}

bool exports_openssl_component_pkey_method_pkey_verify_digest(
        exports_openssl_component_pkey_borrow_pkey_t self,
        exports_openssl_component_pkey_hash_t hash,
        openssl_list_u8_t *digest, openssl_list_u8_t *signature,
        exports_openssl_component_pkey_rsa_padding_t *maybe_padding,
        bool *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    EVP_PKEY *p = as_pkey(self);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(p, NULL);
    if (!ctx || EVP_PKEY_verify_init(ctx) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        err->tag = PE_VERIFY_FAILED; return false;
    }
    const EVP_MD *md = wit_digest_md(hash);
    if (!md) { EVP_PKEY_CTX_free(ctx); err->tag = PE_UNSUPPORTED_TYPE; return false; }
    if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0 ||
        !apply_rsa_padding(ctx, maybe_padding, 1)) {
        EVP_PKEY_CTX_free(ctx);
        err->tag = PE_VERIFY_FAILED; return false;
    }
    int rc = EVP_PKEY_verify(ctx, signature->ptr, signature->len,
                             digest->ptr, digest->len);
    EVP_PKEY_CTX_free(ctx);
    if (rc < 0) {
        err->tag = PE_VERIFY_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    *ret = (rc == 1);
    return true;
}

bool exports_openssl_component_pkey_method_pkey_verify_message(
        exports_openssl_component_pkey_borrow_pkey_t self,
        exports_openssl_component_pkey_hash_t *maybe_hash,
        openssl_list_u8_t *message, openssl_list_u8_t *signature,
        exports_openssl_component_pkey_rsa_padding_t *maybe_padding,
        bool *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    EVP_PKEY *p = as_pkey(self);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { err->tag = PE_INTERNAL; err->val.internal = 0; return false; }

    const EVP_MD *md = NULL;
    if (maybe_hash) {
        md = wit_digest_md(*maybe_hash);
        if (!md) { EVP_MD_CTX_free(mctx); err->tag = PE_UNSUPPORTED_TYPE; return false; }
    }
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestVerifyInit(mctx, &pctx, md, NULL, p) <= 0 ||
        !apply_rsa_padding(pctx, maybe_padding, 1)) {
        EVP_MD_CTX_free(mctx);
        err->tag = PE_VERIFY_FAILED; return false;
    }
    int rc = EVP_DigestVerify(mctx, signature->ptr, signature->len,
                              message->ptr, message->len);
    EVP_MD_CTX_free(mctx);
    if (rc < 0) {
        err->tag = PE_VERIFY_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    *ret = (rc == 1);
    return true;
}

// Encrypt / decrypt (RSA) --------------------------------------------------

bool exports_openssl_component_pkey_method_pkey_encrypt(
        exports_openssl_component_pkey_borrow_pkey_t self,
        exports_openssl_component_pkey_rsa_padding_t *padding,
        openssl_list_u8_t *plaintext, openssl_list_u8_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    EVP_PKEY *p = as_pkey(self);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(p, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 ||
        !apply_rsa_padding(ctx, padding, 0)) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        err->tag = PE_ENCRYPT_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    size_t n = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &n, plaintext->ptr, plaintext->len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        err->tag = PE_ENCRYPT_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->ptr = xmalloc(n ? n : 1); ret->len = n;
    if (EVP_PKEY_encrypt(ctx, ret->ptr, &n, plaintext->ptr, plaintext->len) <= 0) {
        free(ret->ptr); EVP_PKEY_CTX_free(ctx);
        err->tag = PE_ENCRYPT_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->len = n;
    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool exports_openssl_component_pkey_method_pkey_decrypt(
        exports_openssl_component_pkey_borrow_pkey_t self,
        exports_openssl_component_pkey_rsa_padding_t *padding,
        openssl_list_u8_t *ciphertext, openssl_list_u8_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    EVP_PKEY *p = as_pkey(self);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(p, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 ||
        !apply_rsa_padding(ctx, padding, 0)) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        err->tag = PE_DECRYPT_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    size_t n = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &n, ciphertext->ptr, ciphertext->len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        err->tag = PE_DECRYPT_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->ptr = xmalloc(n ? n : 1); ret->len = n;
    if (EVP_PKEY_decrypt(ctx, ret->ptr, &n, ciphertext->ptr, ciphertext->len) <= 0) {
        free(ret->ptr); EVP_PKEY_CTX_free(ctx);
        err->tag = PE_DECRYPT_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->len = n;
    EVP_PKEY_CTX_free(ctx);
    return true;
}

// Derive (ECDH / X25519 / DH) ---------------------------------------------

bool exports_openssl_component_pkey_method_pkey_derive(
        exports_openssl_component_pkey_borrow_pkey_t self,
        exports_openssl_component_pkey_borrow_pkey_t peer,
        openssl_list_u8_t *ret,
        exports_openssl_component_pkey_pkey_error_t *err) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(as_pkey(self), NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, as_pkey(peer)) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        err->tag = PE_DERIVE_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    size_t n = 0;
    if (EVP_PKEY_derive(ctx, NULL, &n) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        err->tag = PE_DERIVE_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->ptr = xmalloc(n ? n : 1); ret->len = n;
    if (EVP_PKEY_derive(ctx, ret->ptr, &n) <= 0) {
        free(ret->ptr); EVP_PKEY_CTX_free(ctx);
        err->tag = PE_DERIVE_FAILED; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->len = n;
    EVP_PKEY_CTX_free(ctx);
    return true;
}

exports_openssl_component_pkey_own_pkey_t
exports_openssl_component_pkey_method_pkey_clone(
        exports_openssl_component_pkey_borrow_pkey_t self) {
    EVP_PKEY *p = as_pkey(self);
    EVP_PKEY_up_ref(p);
    return handle_of(p);
}

void exports_openssl_component_pkey_pkey_destructor(
        exports_openssl_component_pkey_pkey_t *rep) {
    if (rep) EVP_PKEY_free(as_pkey_rep(rep));
}
