// cipher interface — EVP_CIPHER symmetric crypto.

#include "bindings/openssl.h"
#include "include/support.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#define CE_UNSUPPORTED EXPORTS_OPENSSL_COMPONENT_CIPHER_CIPHER_ERROR_UNSUPPORTED_ALGORITHM
#define CE_BAD_KEY     EXPORTS_OPENSSL_COMPONENT_CIPHER_CIPHER_ERROR_BAD_KEY_SIZE
#define CE_BAD_IV      EXPORTS_OPENSSL_COMPONENT_CIPHER_CIPHER_ERROR_BAD_IV_SIZE
#define CE_BAD_TAG     EXPORTS_OPENSSL_COMPONENT_CIPHER_CIPHER_ERROR_BAD_TAG_SIZE
#define CE_BAD_PAD     EXPORTS_OPENSSL_COMPONENT_CIPHER_CIPHER_ERROR_BAD_PADDING
#define CE_AEAD_REQ    EXPORTS_OPENSSL_COMPONENT_CIPHER_CIPHER_ERROR_AEAD_REQUIRED
#define CE_NOT_AEAD    EXPORTS_OPENSSL_COMPONENT_CIPHER_CIPHER_ERROR_NOT_AEAD
#define CE_TAG_MISMATCH EXPORTS_OPENSSL_COMPONENT_CIPHER_CIPHER_ERROR_TAG_MISMATCH
#define CE_INTERNAL    EXPORTS_OPENSSL_COMPONENT_CIPHER_CIPHER_ERROR_INTERNAL

static const EVP_CIPHER *cipher_by_alg(
        exports_openssl_component_cipher_algorithm_t a) {
    switch (a) {
    case 0:  return EVP_aes_128_ecb();
    case 1:  return EVP_aes_192_ecb();
    case 2:  return EVP_aes_256_ecb();
    case 3:  return EVP_aes_128_cbc();
    case 4:  return EVP_aes_192_cbc();
    case 5:  return EVP_aes_256_cbc();
    case 6:  return EVP_aes_128_ctr();
    case 7:  return EVP_aes_192_ctr();
    case 8:  return EVP_aes_256_ctr();
    case 9:  return EVP_aes_128_cfb();
    case 10: return EVP_aes_192_cfb();
    case 11: return EVP_aes_256_cfb();
    case 12: return EVP_aes_128_ofb();
    case 13: return EVP_aes_192_ofb();
    case 14: return EVP_aes_256_ofb();
    case 15: return EVP_aes_128_xts();
    case 16: return EVP_aes_256_xts();
    case 17: return EVP_aes_128_gcm();
    case 18: return EVP_aes_192_gcm();
    case 19: return EVP_aes_256_gcm();
    case 20: return EVP_aes_128_ccm();
    case 21: return EVP_aes_192_ccm();
    case 22: return EVP_aes_256_ccm();
    case 23: return EVP_aes_128_ocb();
    case 24: return EVP_aes_192_ocb();
    case 25: return EVP_aes_256_ocb();
    case 26: return EVP_chacha20();
    case 27: return EVP_chacha20_poly1305();
    case 28: return EVP_camellia_128_cbc();
    case 29: return EVP_camellia_192_cbc();
    case 30: return EVP_camellia_256_cbc();
    case 31: return EVP_aria_128_gcm();
    case 32: return EVP_aria_192_gcm();
    case 33: return EVP_aria_256_gcm();
    case 34: return EVP_sm4_cbc();
    case 35: return NULL;  // SM4-GCM not in 3.x default EVP_* accessors
                           //  TODO: route via EVP_CIPHER_fetch("SM4-GCM")
    case 36: return EVP_des_ede3_cbc();
    case 37: return EVP_rc4();
    default: return NULL;
    }
}

static bool alg_is_aead(exports_openssl_component_cipher_algorithm_t a) {
    switch (a) {
    case 17: case 18: case 19: // AES-GCM
    case 20: case 21: case 22: // AES-CCM
    case 23: case 24: case 25: // AES-OCB
    case 27: // chacha20-poly1305
    case 31: case 32: case 33: // ARIA-GCM
    case 35: // SM4-GCM
        return true;
    default:
        return false;
    }
}

// info ---------------------------------------------------------------------

bool exports_openssl_component_cipher_info(
        exports_openssl_component_cipher_algorithm_t alg,
        exports_openssl_component_cipher_algorithm_info_t *ret,
        exports_openssl_component_cipher_cipher_error_t *err) {
    const EVP_CIPHER *c = cipher_by_alg(alg);
    if (!c) { err->tag = CE_UNSUPPORTED; return false; }
    ret->key_size   = EVP_CIPHER_get_key_length(c);
    ret->iv_size    = EVP_CIPHER_get_iv_length(c);
    ret->block_size = EVP_CIPHER_get_block_size(c);
    ret->is_aead    = alg_is_aead(alg);
    return true;
}

// One-shot non-AEAD --------------------------------------------------------

static bool one_shot(int do_encrypt,
                     exports_openssl_component_cipher_algorithm_t alg,
                     openssl_list_u8_t *key,
                     openssl_list_u8_t *maybe_iv,
                     exports_openssl_component_cipher_padding_mode_t padding,
                     openssl_list_u8_t *in,
                     openssl_list_u8_t *ret,
                     exports_openssl_component_cipher_cipher_error_t *err) {
    const EVP_CIPHER *c = cipher_by_alg(alg);
    if (!c) { err->tag = CE_UNSUPPORTED; return false; }
    if (alg_is_aead(alg)) { err->tag = CE_AEAD_REQ; return false; }

    const unsigned char *iv = maybe_iv ? maybe_iv->ptr : NULL;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { err->tag = CE_INTERNAL; err->val.internal = 0; return false; }

    if (EVP_CipherInit_ex2(ctx, c, key->ptr, iv, do_encrypt, NULL) != 1 ||
        (int)key->len != EVP_CIPHER_CTX_get_key_length(ctx)) {
        EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_BAD_KEY;
        return false;
    }
    EVP_CIPHER_CTX_set_padding(ctx, padding == 1 ? 1 : 0);

    int block = EVP_CIPHER_get_block_size(c);
    int out_len = (int)in->len + block;
    unsigned char *out = xmalloc(out_len > 0 ? out_len : 1);
    int l1 = 0, l2 = 0;
    if (EVP_CipherUpdate(ctx, out, &l1, in->ptr, (int)in->len) != 1) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_INTERNAL;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    if (EVP_CipherFinal_ex(ctx, out + l1, &l2) != 1) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        err->tag = do_encrypt ? CE_INTERNAL : CE_BAD_PAD;
        err->val.internal = ERR_peek_last_error();
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);
    ret->ptr = out;
    ret->len = (size_t)(l1 + l2);
    return true;
}

bool exports_openssl_component_cipher_encrypt(
        exports_openssl_component_cipher_algorithm_t alg,
        openssl_list_u8_t *key, openssl_list_u8_t *iv,
        exports_openssl_component_cipher_padding_mode_t padding,
        openssl_list_u8_t *plaintext, openssl_list_u8_t *ret,
        exports_openssl_component_cipher_cipher_error_t *err) {
    return one_shot(1, alg, key, iv, padding, plaintext, ret, err);
}

bool exports_openssl_component_cipher_decrypt(
        exports_openssl_component_cipher_algorithm_t alg,
        openssl_list_u8_t *key, openssl_list_u8_t *iv,
        exports_openssl_component_cipher_padding_mode_t padding,
        openssl_list_u8_t *ciphertext, openssl_list_u8_t *ret,
        exports_openssl_component_cipher_cipher_error_t *err) {
    return one_shot(0, alg, key, iv, padding, ciphertext, ret, err);
}

// AEAD one-shot ------------------------------------------------------------

static bool is_ccm(exports_openssl_component_cipher_algorithm_t a) {
    return a == 20 || a == 21 || a == 22;
}

bool exports_openssl_component_cipher_seal(
        exports_openssl_component_cipher_algorithm_t alg,
        openssl_list_u8_t *key, openssl_list_u8_t *nonce,
        openssl_list_u8_t *aad, openssl_list_u8_t *plaintext, uint32_t tag_len,
        exports_openssl_component_cipher_aead_sealed_t *ret,
        exports_openssl_component_cipher_cipher_error_t *err) {
    const EVP_CIPHER *c = cipher_by_alg(alg);
    if (!c) { err->tag = CE_UNSUPPORTED; return false; }
    if (!alg_is_aead(alg)) { err->tag = CE_NOT_AEAD; return false; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { err->tag = CE_INTERNAL; err->val.internal = 0; return false; }

    if (EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce->len, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_BAD_IV; return false;
    }
    if (is_ccm(alg)) {
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag_len, NULL);
    }
    if (EVP_EncryptInit_ex2(ctx, NULL, key->ptr, nonce->ptr, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_BAD_KEY; return false;
    }
    int dummy = 0;
    if (is_ccm(alg)) {
        // For CCM, set the total plaintext length before AAD.
        EVP_EncryptUpdate(ctx, NULL, &dummy, NULL, (int)plaintext->len);
    }
    if (aad->len && EVP_EncryptUpdate(ctx, NULL, &dummy, aad->ptr, (int)aad->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }

    unsigned char *ct = xmalloc(plaintext->len ? plaintext->len : 1);
    int l1 = 0, l2 = 0;
    if (EVP_EncryptUpdate(ctx, ct, &l1, plaintext->ptr, (int)plaintext->len) != 1) {
        free(ct); EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }
    if (EVP_EncryptFinal_ex(ctx, ct + l1, &l2) != 1) {
        free(ct); EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }

    unsigned char *tag = xmalloc(tag_len ? tag_len : 1);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)tag_len, tag) != 1) {
        free(ct); free(tag); EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_BAD_TAG; return false;
    }
    EVP_CIPHER_CTX_free(ctx);

    ret->ciphertext.ptr = ct;
    ret->ciphertext.len = (size_t)(l1 + l2);
    ret->tag.ptr = tag;
    ret->tag.len = tag_len;
    return true;
}

bool exports_openssl_component_cipher_open(
        exports_openssl_component_cipher_algorithm_t alg,
        openssl_list_u8_t *key, openssl_list_u8_t *nonce,
        openssl_list_u8_t *aad, openssl_list_u8_t *ciphertext,
        openssl_list_u8_t *tag, openssl_list_u8_t *ret,
        exports_openssl_component_cipher_cipher_error_t *err) {
    const EVP_CIPHER *c = cipher_by_alg(alg);
    if (!c) { err->tag = CE_UNSUPPORTED; return false; }
    if (!alg_is_aead(alg)) { err->tag = CE_NOT_AEAD; return false; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { err->tag = CE_INTERNAL; err->val.internal = 0; return false; }

    if (EVP_DecryptInit_ex2(ctx, c, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce->len, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_BAD_IV; return false;
    }
    if (is_ccm(alg)) {
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag->len, tag->ptr);
    }
    if (EVP_DecryptInit_ex2(ctx, NULL, key->ptr, nonce->ptr, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_BAD_KEY; return false;
    }
    int dummy = 0;
    if (is_ccm(alg)) {
        EVP_DecryptUpdate(ctx, NULL, &dummy, NULL, (int)ciphertext->len);
    }
    if (aad->len && EVP_DecryptUpdate(ctx, NULL, &dummy, aad->ptr, (int)aad->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }

    unsigned char *pt = xmalloc(ciphertext->len ? ciphertext->len : 1);
    int l1 = 0, l2 = 0;
    if (EVP_DecryptUpdate(ctx, pt, &l1, ciphertext->ptr, (int)ciphertext->len) != 1) {
        free(pt); EVP_CIPHER_CTX_free(ctx);
        err->tag = CE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }
    if (!is_ccm(alg)) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                (int)tag->len, tag->ptr) != 1) {
            free(pt); EVP_CIPHER_CTX_free(ctx);
            err->tag = CE_BAD_TAG; return false;
        }
    }
    int ok = EVP_DecryptFinal_ex(ctx, pt + l1, &l2);
    EVP_CIPHER_CTX_free(ctx);
    if (ok != 1) {
        free(pt);
        err->tag = CE_TAG_MISMATCH;
        return false;
    }
    ret->ptr = pt;
    ret->len = (size_t)(l1 + l2);
    return true;
}

// Streaming ---------------------------------------------------------------
//
// Encryptor & decryptor reps keep a CTX plus the algorithm tag for AEAD
// finish semantics.

typedef struct encryptor_rep {
    EVP_CIPHER_CTX *ctx;
    exports_openssl_component_cipher_algorithm_t alg;
    int tag_len;
} encryptor_rep;

typedef struct decryptor_rep {
    EVP_CIPHER_CTX *ctx;
    exports_openssl_component_cipher_algorithm_t alg;
} decryptor_rep;

typedef struct exports_openssl_component_cipher_encryptor_t encryptor_rep_opaque;
typedef struct exports_openssl_component_cipher_decryptor_t decryptor_rep_opaque;

// Keep the tag-setting default for the streaming encryptor:
// 16 for GCM/OCB/ChaCha20-Poly1305, 16 for CCM (configurable), 16 for ARIA-GCM.
static int default_tag_len(exports_openssl_component_cipher_algorithm_t a) {
    (void)a;
    return 16;
}

exports_openssl_component_cipher_own_encryptor_t
exports_openssl_component_cipher_constructor_encryptor(
        exports_openssl_component_cipher_algorithm_t alg,
        openssl_list_u8_t *key, openssl_list_u8_t *maybe_iv,
        exports_openssl_component_cipher_padding_mode_t padding) {
    encryptor_rep *r = xmalloc(sizeof(*r));
    r->alg = alg;
    r->tag_len = default_tag_len(alg);
    r->ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *c = cipher_by_alg(alg);
    if (r->ctx && c) {
        const unsigned char *iv = maybe_iv ? maybe_iv->ptr : NULL;
        EVP_EncryptInit_ex2(r->ctx, c, key->ptr, iv, NULL);
        EVP_CIPHER_CTX_set_padding(r->ctx, padding == 1 ? 1 : 0);
    }
    return exports_openssl_component_cipher_encryptor_new(
        (exports_openssl_component_cipher_encryptor_t *)r);
}

bool exports_openssl_component_cipher_method_encryptor_set_aad(
        exports_openssl_component_cipher_borrow_encryptor_t self,
        openssl_list_u8_t *aad,
        exports_openssl_component_cipher_cipher_error_t *err) {
    encryptor_rep *r = (encryptor_rep *)self;
    if (!alg_is_aead(r->alg)) { err->tag = CE_NOT_AEAD; return false; }
    int dummy = 0;
    if (EVP_EncryptUpdate(r->ctx, NULL, &dummy, aad->ptr, (int)aad->len) != 1) {
        err->tag = CE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }
    return true;
}

bool exports_openssl_component_cipher_method_encryptor_update(
        exports_openssl_component_cipher_borrow_encryptor_t self,
        openssl_list_u8_t *plaintext, openssl_list_u8_t *ret,
        exports_openssl_component_cipher_cipher_error_t *err) {
    encryptor_rep *r = (encryptor_rep *)self;
    int block = EVP_CIPHER_CTX_get_block_size(r->ctx);
    int out_cap = (int)plaintext->len + block;
    ret->ptr = xmalloc(out_cap > 0 ? out_cap : 1);
    int l = 0;
    if (EVP_EncryptUpdate(r->ctx, ret->ptr, &l,
                          plaintext->ptr, (int)plaintext->len) != 1) {
        free(ret->ptr);
        err->tag = CE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->len = (size_t)l;
    return true;
}

bool exports_openssl_component_cipher_static_encryptor_finish(
        exports_openssl_component_cipher_own_encryptor_t handle,
        openssl_tuple2_list_u8_option_list_u8_t *ret,
        exports_openssl_component_cipher_cipher_error_t *err) {
    encryptor_rep *r = (encryptor_rep *)
        exports_openssl_component_cipher_encryptor_rep(handle);
    int block = EVP_CIPHER_CTX_get_block_size(r->ctx);
    ret->f0.ptr = xmalloc(block > 0 ? block : 1);
    int l = 0;
    int ok = EVP_EncryptFinal_ex(r->ctx, ret->f0.ptr, &l);
    if (!ok) {
        free(ret->f0.ptr);
        exports_openssl_component_cipher_encryptor_drop_own(handle);
        err->tag = CE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->f0.len = (size_t)l;

    if (alg_is_aead(r->alg)) {
        ret->f1.is_some = true;
        ret->f1.val.ptr = xmalloc(r->tag_len);
        ret->f1.val.len = r->tag_len;
        if (EVP_CIPHER_CTX_ctrl(r->ctx, EVP_CTRL_AEAD_GET_TAG,
                                r->tag_len, ret->f1.val.ptr) != 1) {
            free(ret->f0.ptr); free(ret->f1.val.ptr);
            exports_openssl_component_cipher_encryptor_drop_own(handle);
            err->tag = CE_BAD_TAG; return false;
        }
    } else {
        ret->f1.is_some = false;
    }

    exports_openssl_component_cipher_encryptor_drop_own(handle);
    return true;
}

exports_openssl_component_cipher_own_decryptor_t
exports_openssl_component_cipher_constructor_decryptor(
        exports_openssl_component_cipher_algorithm_t alg,
        openssl_list_u8_t *key, openssl_list_u8_t *maybe_iv,
        exports_openssl_component_cipher_padding_mode_t padding) {
    decryptor_rep *r = xmalloc(sizeof(*r));
    r->alg = alg;
    r->ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *c = cipher_by_alg(alg);
    if (r->ctx && c) {
        const unsigned char *iv = maybe_iv ? maybe_iv->ptr : NULL;
        EVP_DecryptInit_ex2(r->ctx, c, key->ptr, iv, NULL);
        EVP_CIPHER_CTX_set_padding(r->ctx, padding == 1 ? 1 : 0);
    }
    return exports_openssl_component_cipher_decryptor_new(
        (exports_openssl_component_cipher_decryptor_t *)r);
}

bool exports_openssl_component_cipher_method_decryptor_set_aad(
        exports_openssl_component_cipher_borrow_decryptor_t self,
        openssl_list_u8_t *aad,
        exports_openssl_component_cipher_cipher_error_t *err) {
    decryptor_rep *r = (decryptor_rep *)self;
    if (!alg_is_aead(r->alg)) { err->tag = CE_NOT_AEAD; return false; }
    int dummy = 0;
    if (EVP_DecryptUpdate(r->ctx, NULL, &dummy, aad->ptr, (int)aad->len) != 1) {
        err->tag = CE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }
    return true;
}

bool exports_openssl_component_cipher_method_decryptor_set_tag(
        exports_openssl_component_cipher_borrow_decryptor_t self,
        openssl_list_u8_t *tag,
        exports_openssl_component_cipher_cipher_error_t *err) {
    decryptor_rep *r = (decryptor_rep *)self;
    if (!alg_is_aead(r->alg)) { err->tag = CE_NOT_AEAD; return false; }
    if (EVP_CIPHER_CTX_ctrl(r->ctx, EVP_CTRL_AEAD_SET_TAG,
                            (int)tag->len, tag->ptr) != 1) {
        err->tag = CE_BAD_TAG; return false;
    }
    return true;
}

bool exports_openssl_component_cipher_method_decryptor_update(
        exports_openssl_component_cipher_borrow_decryptor_t self,
        openssl_list_u8_t *ciphertext, openssl_list_u8_t *ret,
        exports_openssl_component_cipher_cipher_error_t *err) {
    decryptor_rep *r = (decryptor_rep *)self;
    int block = EVP_CIPHER_CTX_get_block_size(r->ctx);
    int out_cap = (int)ciphertext->len + block;
    ret->ptr = xmalloc(out_cap > 0 ? out_cap : 1);
    int l = 0;
    if (EVP_DecryptUpdate(r->ctx, ret->ptr, &l,
                          ciphertext->ptr, (int)ciphertext->len) != 1) {
        free(ret->ptr);
        err->tag = CE_INTERNAL; err->val.internal = ERR_peek_last_error();
        return false;
    }
    ret->len = (size_t)l;
    return true;
}

bool exports_openssl_component_cipher_static_decryptor_finish(
        exports_openssl_component_cipher_own_decryptor_t handle,
        openssl_list_u8_t *ret,
        exports_openssl_component_cipher_cipher_error_t *err) {
    decryptor_rep *r = (decryptor_rep *)
        exports_openssl_component_cipher_decryptor_rep(handle);
    int block = EVP_CIPHER_CTX_get_block_size(r->ctx);
    ret->ptr = xmalloc(block > 0 ? block : 1);
    int l = 0;
    int ok = EVP_DecryptFinal_ex(r->ctx, ret->ptr, &l);
    exports_openssl_component_cipher_decryptor_drop_own(handle);
    if (!ok) {
        free(ret->ptr);
        err->tag = alg_is_aead(r->alg) ? CE_TAG_MISMATCH : CE_BAD_PAD;
        return false;
    }
    ret->len = (size_t)l;
    return true;
}

// Destructors --------------------------------------------------------------

void exports_openssl_component_cipher_encryptor_destructor(
        exports_openssl_component_cipher_encryptor_t *rep) {
    encryptor_rep *r = (encryptor_rep *)rep;
    if (!r) return;
    if (r->ctx) EVP_CIPHER_CTX_free(r->ctx);
    free(r);
}

void exports_openssl_component_cipher_decryptor_destructor(
        exports_openssl_component_cipher_decryptor_t *rep) {
    decryptor_rep *r = (decryptor_rep *)rep;
    if (!r) return;
    if (r->ctx) EVP_CIPHER_CTX_free(r->ctx);
    free(r);
}
