// noop-provider — trivial implementation of openssl:provider-abi.
//
// Phase 2 verification helper. Every function returns either "empty
// success" (provider-level funcs openssl-wasm actually calls during
// SSL_CTX_new) or `pkey-error::not-supported` (keymgmt/signature/
// asym-cipher methods that are never invoked because query_operation
// always returns no algorithms).

#include "noop.h"
#include <string.h>

static void make_not_supported(exports_openssl_pkey_pkey_pkey_error_t *err,
                               const char *msg) {
    err->tag = EXPORTS_OPENSSL_PKEY_PKEY_PKEY_ERROR_NOT_SUPPORTED;
    noop_string_dup(&err->val.not_supported, msg);
}

// All per-interface pkey-error types alias the canonical pkey one.
#define ERR_NS(p) \
    make_not_supported((exports_openssl_pkey_pkey_pkey_error_t *)(p), "noop")

// =========================================================================
// PROVIDER
// =========================================================================

void exports_openssl_provider_provider_gettable_params(
        exports_openssl_provider_provider_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}

bool exports_openssl_provider_provider_get_params(
        noop_list_string_t *keys,
        exports_openssl_provider_provider_list_ossl_param_t *ret,
        exports_openssl_provider_provider_pkey_error_t *err) {
    (void)keys; (void)err;
    ret->ptr = NULL; ret->len = 0;
    return true;
}

void exports_openssl_provider_provider_query_operation(
        exports_openssl_provider_provider_operation_t op,
        exports_openssl_provider_provider_tuple2_list_ossl_algorithm_bool_t *ret) {
    (void)op;
    ret->f0.ptr = NULL; ret->f0.len = 0;
    ret->f1 = true;  // no_store
}

void exports_openssl_provider_provider_unquery_operation(
        exports_openssl_provider_provider_operation_t op,
        exports_openssl_provider_provider_list_ossl_algorithm_t *algorithms) {
    (void)op; (void)algorithms;
}

void exports_openssl_provider_provider_get_reason_strings(
        exports_openssl_provider_provider_list_ossl_reason_string_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}

bool exports_openssl_provider_provider_get_capabilities(
        noop_string_t *capability,
        exports_openssl_provider_provider_list_list_ossl_param_t *ret,
        exports_openssl_provider_provider_pkey_error_t *err) {
    (void)capability; (void)err;
    ret->ptr = NULL; ret->len = 0;
    return true;
}

bool exports_openssl_provider_provider_self_test(
        exports_openssl_provider_provider_pkey_error_t *err) {
    (void)err;
    return true;
}

bool exports_openssl_provider_provider_random_bytes(
        exports_openssl_provider_provider_random_source_t which,
        uint64_t n, uint32_t strength,
        noop_list_u8_t *ret,
        exports_openssl_provider_provider_pkey_error_t *err) {
    (void)which; (void)n; (void)strength; (void)ret;
    ERR_NS(err);
    return false;
}

// =========================================================================
// KEYMGMT — top-level + keydata + gen-context (Phase 3 WIT refactor:
// keydata and gen-context are now resources owned by keymgmt, no
// separate _methods type)
// =========================================================================

bool exports_openssl_keymgmt_keymgmt_query_operation_name(
        exports_openssl_keymgmt_keymgmt_operation_t op,
        noop_string_t *ret) {
    (void)op; (void)ret;
    return false;
}
void exports_openssl_keymgmt_keymgmt_gettable_params(
        exports_openssl_keymgmt_keymgmt_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}
void exports_openssl_keymgmt_keymgmt_settable_params(
        exports_openssl_keymgmt_keymgmt_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}
void exports_openssl_keymgmt_keymgmt_import_types(
        exports_openssl_keymgmt_keymgmt_key_selection_t sel,
        exports_openssl_keymgmt_keymgmt_list_ossl_param_descriptor_t *ret) {
    (void)sel; ret->ptr = NULL; ret->len = 0;
}
void exports_openssl_keymgmt_keymgmt_export_types(
        exports_openssl_keymgmt_keymgmt_key_selection_t sel,
        exports_openssl_keymgmt_keymgmt_list_ossl_param_descriptor_t *ret) {
    (void)sel; ret->ptr = NULL; ret->len = 0;
}
void exports_openssl_keymgmt_keymgmt_import_types_ex(
        exports_openssl_keymgmt_keymgmt_key_selection_t sel,
        exports_openssl_keymgmt_keymgmt_list_ossl_param_descriptor_t *ret) {
    (void)sel; ret->ptr = NULL; ret->len = 0;
}
void exports_openssl_keymgmt_keymgmt_export_types_ex(
        exports_openssl_keymgmt_keymgmt_key_selection_t sel,
        exports_openssl_keymgmt_keymgmt_list_ossl_param_descriptor_t *ret) {
    (void)sel; ret->ptr = NULL; ret->len = 0;
}
bool exports_openssl_keymgmt_keymgmt_load(
        noop_list_u8_t *ref,
        exports_openssl_keymgmt_keymgmt_own_keydata_t *ret,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)ref; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_keymgmt_keymgmt_gen_init(
        exports_openssl_keymgmt_keymgmt_key_selection_t sel,
        exports_openssl_keymgmt_keymgmt_list_ossl_param_t *params,
        exports_openssl_keymgmt_keymgmt_own_gen_context_t *ret,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)sel; (void)params; (void)ret; ERR_NS(err); return false;
}
void exports_openssl_keymgmt_keymgmt_gen_settable_params(
        exports_openssl_keymgmt_keymgmt_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}
void exports_openssl_keymgmt_keymgmt_gen_gettable_params(
        exports_openssl_keymgmt_keymgmt_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}

// keydata resource
void exports_openssl_keymgmt_keymgmt_keydata_destructor(
        exports_openssl_keymgmt_keymgmt_keydata_t *obj) {
    (void)obj;
}
exports_openssl_keymgmt_keymgmt_own_keydata_t
exports_openssl_keymgmt_keymgmt_constructor_keydata(void) {
    return (exports_openssl_keymgmt_keymgmt_own_keydata_t){ 0 };
}
bool exports_openssl_keymgmt_keymgmt_method_keydata_get_params(
        exports_openssl_keymgmt_keymgmt_borrow_keydata_t self,
        noop_list_string_t *keys,
        exports_openssl_keymgmt_keymgmt_list_ossl_param_t *ret,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)self; (void)keys; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_keymgmt_keymgmt_method_keydata_set_params(
        exports_openssl_keymgmt_keymgmt_borrow_keydata_t self,
        exports_openssl_keymgmt_keymgmt_list_ossl_param_t *params,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)self; (void)params; ERR_NS(err); return false;
}
bool exports_openssl_keymgmt_keymgmt_method_keydata_has(
        exports_openssl_keymgmt_keymgmt_borrow_keydata_t self,
        exports_openssl_keymgmt_keymgmt_key_selection_t sel) {
    (void)self; (void)sel; return false;
}
bool exports_openssl_keymgmt_keymgmt_method_keydata_validate(
        exports_openssl_keymgmt_keymgmt_borrow_keydata_t self,
        exports_openssl_keymgmt_keymgmt_key_selection_t sel,
        exports_openssl_keymgmt_keymgmt_validation_level_t lvl,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)self; (void)sel; (void)lvl; ERR_NS(err); return false;
}
bool exports_openssl_keymgmt_keymgmt_method_keydata_match(
        exports_openssl_keymgmt_keymgmt_borrow_keydata_t self,
        exports_openssl_keymgmt_keymgmt_borrow_keydata_t other,
        exports_openssl_keymgmt_keymgmt_key_selection_t sel) {
    (void)self; (void)other; (void)sel; return false;
}
bool exports_openssl_keymgmt_keymgmt_method_keydata_import(
        exports_openssl_keymgmt_keymgmt_borrow_keydata_t self,
        exports_openssl_keymgmt_keymgmt_key_selection_t sel,
        exports_openssl_keymgmt_keymgmt_list_ossl_param_t *params,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)self; (void)sel; (void)params; ERR_NS(err); return false;
}
bool exports_openssl_keymgmt_keymgmt_method_keydata_export(
        exports_openssl_keymgmt_keymgmt_borrow_keydata_t self,
        exports_openssl_keymgmt_keymgmt_key_selection_t sel,
        exports_openssl_keymgmt_keymgmt_list_list_ossl_param_t *ret,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)self; (void)sel; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_keymgmt_keymgmt_method_keydata_dup(
        exports_openssl_keymgmt_keymgmt_borrow_keydata_t self,
        exports_openssl_keymgmt_keymgmt_key_selection_t sel,
        exports_openssl_keymgmt_keymgmt_own_keydata_t *ret,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)self; (void)sel; (void)ret; ERR_NS(err); return false;
}

// gen-context resource
void exports_openssl_keymgmt_keymgmt_gen_context_destructor(
        exports_openssl_keymgmt_keymgmt_gen_context_t *obj) {
    (void)obj;
}
bool exports_openssl_keymgmt_keymgmt_method_gen_context_set_template(
        exports_openssl_keymgmt_keymgmt_borrow_gen_context_t self,
        exports_openssl_keymgmt_keymgmt_borrow_keydata_t tmpl,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)self; (void)tmpl; ERR_NS(err); return false;
}
bool exports_openssl_keymgmt_keymgmt_method_gen_context_set_params(
        exports_openssl_keymgmt_keymgmt_borrow_gen_context_t self,
        exports_openssl_keymgmt_keymgmt_list_ossl_param_t *params,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)self; (void)params; ERR_NS(err); return false;
}
bool exports_openssl_keymgmt_keymgmt_method_gen_context_get_params(
        exports_openssl_keymgmt_keymgmt_borrow_gen_context_t self,
        noop_list_string_t *keys,
        exports_openssl_keymgmt_keymgmt_list_ossl_param_t *ret,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)self; (void)keys; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_keymgmt_keymgmt_method_gen_context_gen(
        exports_openssl_keymgmt_keymgmt_borrow_gen_context_t self,
        exports_openssl_keymgmt_keymgmt_own_keydata_t *ret,
        exports_openssl_keymgmt_keymgmt_pkey_error_t *err) {
    (void)self; (void)ret; ERR_NS(err); return false;
}

// =========================================================================
// SIGNATURE
// =========================================================================

void exports_openssl_signature_signature_query_key_types(
        noop_list_string_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}
void exports_openssl_signature_signature_gettable_ctx_params(
        exports_openssl_signature_signature_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}
void exports_openssl_signature_signature_settable_ctx_params(
        exports_openssl_signature_signature_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}

void exports_openssl_signature_signature_signature_context_destructor(
        exports_openssl_signature_signature_signature_context_t *obj) {
    (void)obj;
}
exports_openssl_signature_signature_own_signature_context_t
exports_openssl_signature_signature_constructor_signature_context(
        noop_string_t *propq) {
    (void)propq;
    return (exports_openssl_signature_signature_own_signature_context_t){ 0 };
}
bool exports_openssl_signature_signature_method_signature_context_dup(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        exports_openssl_signature_signature_own_signature_context_t *ret,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_sign_init(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        exports_openssl_signature_signature_borrow_keydata_t key,
        exports_openssl_signature_signature_list_ossl_param_t *params,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)key; (void)params; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_sign(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_list_u8_t *tbs, noop_list_u8_t *ret,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)tbs; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_verify_init(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        exports_openssl_signature_signature_borrow_keydata_t key,
        exports_openssl_signature_signature_list_ossl_param_t *params,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)key; (void)params; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_verify(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_list_u8_t *sig, noop_list_u8_t *tbs,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)sig; (void)tbs; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_verify_recover_init(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        exports_openssl_signature_signature_borrow_keydata_t key,
        exports_openssl_signature_signature_list_ossl_param_t *params,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)key; (void)params; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_verify_recover(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_list_u8_t *sig, noop_list_u8_t *ret,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)sig; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_digest_sign_init(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_string_t *md, exports_openssl_signature_signature_borrow_keydata_t key,
        exports_openssl_signature_signature_list_ossl_param_t *params,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)md; (void)key; (void)params; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_digest_sign_update(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_list_u8_t *data,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)data; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_digest_sign_final(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_list_u8_t *ret,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_digest_sign(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_list_u8_t *tbs, noop_list_u8_t *ret,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)tbs; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_digest_verify_init(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_string_t *md, exports_openssl_signature_signature_borrow_keydata_t key,
        exports_openssl_signature_signature_list_ossl_param_t *params,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)md; (void)key; (void)params; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_digest_verify_update(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_list_u8_t *data,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)data; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_digest_verify_final(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_list_u8_t *sig,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)sig; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_digest_verify(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_list_u8_t *sig, noop_list_u8_t *tbs,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)sig; (void)tbs; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_get_ctx_params(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_list_string_t *keys,
        exports_openssl_signature_signature_list_ossl_param_t *ret,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)keys; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_set_ctx_params(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        exports_openssl_signature_signature_list_ossl_param_t *params,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)params; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_get_ctx_md_params(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        noop_list_string_t *keys,
        exports_openssl_signature_signature_list_ossl_param_t *ret,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)keys; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_signature_signature_method_signature_context_set_ctx_md_params(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        exports_openssl_signature_signature_list_ossl_param_t *params,
        exports_openssl_signature_signature_pkey_error_t *err) {
    (void)self; (void)params; ERR_NS(err); return false;
}
void exports_openssl_signature_signature_method_signature_context_gettable_ctx_md_params(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        exports_openssl_signature_signature_list_ossl_param_descriptor_t *ret) {
    (void)self; ret->ptr = NULL; ret->len = 0;
}
void exports_openssl_signature_signature_method_signature_context_settable_ctx_md_params(
        exports_openssl_signature_signature_borrow_signature_context_t self,
        exports_openssl_signature_signature_list_ossl_param_descriptor_t *ret) {
    (void)self; ret->ptr = NULL; ret->len = 0;
}

// =========================================================================
// ASYM-CIPHER
// =========================================================================

void exports_openssl_asym_cipher_asym_cipher_gettable_ctx_params(
        exports_openssl_asym_cipher_asym_cipher_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}
void exports_openssl_asym_cipher_asym_cipher_settable_ctx_params(
        exports_openssl_asym_cipher_asym_cipher_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}

void exports_openssl_asym_cipher_asym_cipher_asym_cipher_context_destructor(
        exports_openssl_asym_cipher_asym_cipher_asym_cipher_context_t *obj) {
    (void)obj;
}
exports_openssl_asym_cipher_asym_cipher_own_asym_cipher_context_t
exports_openssl_asym_cipher_asym_cipher_constructor_asym_cipher_context(void) {
    return (exports_openssl_asym_cipher_asym_cipher_own_asym_cipher_context_t){ 0 };
}
bool exports_openssl_asym_cipher_asym_cipher_method_asym_cipher_context_dup(
        exports_openssl_asym_cipher_asym_cipher_borrow_asym_cipher_context_t self,
        exports_openssl_asym_cipher_asym_cipher_own_asym_cipher_context_t *ret,
        exports_openssl_asym_cipher_asym_cipher_pkey_error_t *err) {
    (void)self; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_asym_cipher_asym_cipher_method_asym_cipher_context_encrypt_init(
        exports_openssl_asym_cipher_asym_cipher_borrow_asym_cipher_context_t self,
        exports_openssl_asym_cipher_asym_cipher_borrow_keydata_t key,
        exports_openssl_asym_cipher_asym_cipher_list_ossl_param_t *params,
        exports_openssl_asym_cipher_asym_cipher_pkey_error_t *err) {
    (void)self; (void)key; (void)params; ERR_NS(err); return false;
}
bool exports_openssl_asym_cipher_asym_cipher_method_asym_cipher_context_encrypt(
        exports_openssl_asym_cipher_asym_cipher_borrow_asym_cipher_context_t self,
        noop_list_u8_t *pt, noop_list_u8_t *ret,
        exports_openssl_asym_cipher_asym_cipher_pkey_error_t *err) {
    (void)self; (void)pt; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_asym_cipher_asym_cipher_method_asym_cipher_context_decrypt_init(
        exports_openssl_asym_cipher_asym_cipher_borrow_asym_cipher_context_t self,
        exports_openssl_asym_cipher_asym_cipher_borrow_keydata_t key,
        exports_openssl_asym_cipher_asym_cipher_list_ossl_param_t *params,
        exports_openssl_asym_cipher_asym_cipher_pkey_error_t *err) {
    (void)self; (void)key; (void)params; ERR_NS(err); return false;
}
bool exports_openssl_asym_cipher_asym_cipher_method_asym_cipher_context_decrypt(
        exports_openssl_asym_cipher_asym_cipher_borrow_asym_cipher_context_t self,
        noop_list_u8_t *ct, noop_list_u8_t *ret,
        exports_openssl_asym_cipher_asym_cipher_pkey_error_t *err) {
    (void)self; (void)ct; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_asym_cipher_asym_cipher_method_asym_cipher_context_get_ctx_params(
        exports_openssl_asym_cipher_asym_cipher_borrow_asym_cipher_context_t self,
        noop_list_string_t *keys,
        exports_openssl_asym_cipher_asym_cipher_list_ossl_param_t *ret,
        exports_openssl_asym_cipher_asym_cipher_pkey_error_t *err) {
    (void)self; (void)keys; (void)ret; ERR_NS(err); return false;
}
bool exports_openssl_asym_cipher_asym_cipher_method_asym_cipher_context_set_ctx_params(
        exports_openssl_asym_cipher_asym_cipher_borrow_asym_cipher_context_t self,
        exports_openssl_asym_cipher_asym_cipher_list_ossl_param_t *params,
        exports_openssl_asym_cipher_asym_cipher_pkey_error_t *err) {
    (void)self; (void)params; ERR_NS(err); return false;
}

// PKEY no longer has resources -- the refactored WIT moved them to
// keymgmt/signature/asym-cipher where their methods live.

// =========================================================================
// STORE  (Phase 8) — every loader is a no-op. supported-schemes=[]
// keeps OpenSSL from ever calling constructor_loader, so the body of
// each loader method is unreachable in practice; we still implement
// them so wac plug can satisfy the openssl-wasm import.
// =========================================================================

void exports_openssl_store_store_settable_ctx_params(
        exports_openssl_store_store_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}

void exports_openssl_store_store_supported_schemes(noop_list_string_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}

bool exports_openssl_store_store_delete(noop_string_t *uri,
                                        exports_openssl_store_store_pkey_error_t *err) {
    (void)uri; ERR_NS(err); return false;
}

// Minimal `rep` -- just one byte; resource-rep round-trips need a
// stable non-NULL pointer per WIT borrow semantics.
typedef struct { uint8_t marker; } noop_loader_rep_t;
static noop_loader_rep_t g_noop_loader = { 0xAA };

exports_openssl_store_store_own_loader_t
exports_openssl_store_store_constructor_loader(noop_string_t *uri) {
    (void)uri;
    return exports_openssl_store_store_loader_new(
        (exports_openssl_store_store_loader_t *)&g_noop_loader);
}

void exports_openssl_store_store_loader_destructor(
        exports_openssl_store_store_loader_t *rep) {
    (void)rep;  // static singleton; nothing to free
}

bool exports_openssl_store_store_method_loader_set_ctx_params(
        exports_openssl_store_store_borrow_loader_t self,
        exports_openssl_store_store_list_ossl_param_t *params,
        exports_openssl_store_store_pkey_error_t *err) {
    (void)self; (void)params; (void)err;
    return true;
}

bool exports_openssl_store_store_method_loader_load(
        exports_openssl_store_store_borrow_loader_t self,
        exports_openssl_store_store_option_store_object_t *ret,
        exports_openssl_store_store_pkey_error_t *err) {
    (void)self; (void)err;
    ret->is_some = false;
    return true;
}

bool exports_openssl_store_store_method_loader_eof(
        exports_openssl_store_store_borrow_loader_t self) {
    (void)self; return true;
}

// =========================================================================
// ENCODER (Phase 8) — no-op. provider.query-operation(encoder) returns
// no algorithms, so the resource methods below are unreachable in
// practice; we still implement them so wac plug can satisfy
// openssl-wasm's import.
// =========================================================================

void exports_openssl_encoder_encoder_gettable_params(
        exports_openssl_encoder_encoder_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}

void exports_openssl_encoder_encoder_settable_ctx_params(
        exports_openssl_encoder_encoder_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}

bool exports_openssl_encoder_encoder_does_selection(
        exports_openssl_encoder_encoder_key_selection_t selection) {
    (void)selection; return false;
}

typedef struct { uint8_t marker; } noop_encode_ctx_rep_t;
static noop_encode_ctx_rep_t g_noop_encode_ctx = { 0xEE };

exports_openssl_encoder_encoder_own_encode_ctx_t
exports_openssl_encoder_encoder_constructor_encode_ctx(void) {
    return exports_openssl_encoder_encoder_encode_ctx_new(
        (exports_openssl_encoder_encoder_encode_ctx_t *)&g_noop_encode_ctx);
}

void exports_openssl_encoder_encoder_encode_ctx_destructor(
        exports_openssl_encoder_encoder_encode_ctx_t *rep) { (void)rep; }

bool exports_openssl_encoder_encoder_method_encode_ctx_get_params(
        exports_openssl_encoder_encoder_borrow_encode_ctx_t self,
        exports_openssl_encoder_encoder_list_ossl_param_t *ret,
        exports_openssl_encoder_encoder_pkey_error_t *err) {
    (void)self; (void)err; ret->ptr = NULL; ret->len = 0; return true;
}

bool exports_openssl_encoder_encoder_method_encode_ctx_set_ctx_params(
        exports_openssl_encoder_encoder_borrow_encode_ctx_t self,
        exports_openssl_encoder_encoder_list_ossl_param_t *params,
        exports_openssl_encoder_encoder_pkey_error_t *err) {
    (void)self; (void)params; (void)err; return true;
}

bool exports_openssl_encoder_encoder_method_encode_ctx_import_object(
        exports_openssl_encoder_encoder_borrow_encode_ctx_t self,
        exports_openssl_encoder_encoder_key_selection_t selection,
        exports_openssl_encoder_encoder_list_ossl_param_t *params,
        exports_openssl_encoder_encoder_own_keydata_t *ret,
        exports_openssl_encoder_encoder_pkey_error_t *err) {
    (void)self; (void)selection; (void)params; (void)ret;
    ERR_NS(err); return false;
}

bool exports_openssl_encoder_encoder_method_encode_ctx_encode(
        exports_openssl_encoder_encoder_borrow_encode_ctx_t self,
        exports_openssl_encoder_encoder_borrow_keydata_t obj,
        exports_openssl_encoder_encoder_key_selection_t selection,
        noop_list_u8_t *ret,
        exports_openssl_encoder_encoder_pkey_error_t *err) {
    (void)self; (void)obj; (void)selection; (void)ret;
    ERR_NS(err); return false;
}

// =========================================================================
// DECODER (Phase 8) — symmetric no-op.
// =========================================================================

void exports_openssl_decoder_decoder_gettable_params(
        exports_openssl_decoder_decoder_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}

void exports_openssl_decoder_decoder_settable_ctx_params(
        exports_openssl_decoder_decoder_list_ossl_param_descriptor_t *ret) {
    ret->ptr = NULL; ret->len = 0;
}

bool exports_openssl_decoder_decoder_does_selection(
        exports_openssl_decoder_decoder_key_selection_t selection) {
    (void)selection; return false;
}

typedef struct { uint8_t marker; } noop_decode_ctx_rep_t;
static noop_decode_ctx_rep_t g_noop_decode_ctx = { 0xDD };

exports_openssl_decoder_decoder_own_decode_ctx_t
exports_openssl_decoder_decoder_constructor_decode_ctx(void) {
    return exports_openssl_decoder_decoder_decode_ctx_new(
        (exports_openssl_decoder_decoder_decode_ctx_t *)&g_noop_decode_ctx);
}

void exports_openssl_decoder_decoder_decode_ctx_destructor(
        exports_openssl_decoder_decoder_decode_ctx_t *rep) { (void)rep; }

bool exports_openssl_decoder_decoder_method_decode_ctx_get_params(
        exports_openssl_decoder_decoder_borrow_decode_ctx_t self,
        exports_openssl_decoder_decoder_list_ossl_param_t *ret,
        exports_openssl_decoder_decoder_pkey_error_t *err) {
    (void)self; (void)err; ret->ptr = NULL; ret->len = 0; return true;
}

bool exports_openssl_decoder_decoder_method_decode_ctx_set_ctx_params(
        exports_openssl_decoder_decoder_borrow_decode_ctx_t self,
        exports_openssl_decoder_decoder_list_ossl_param_t *params,
        exports_openssl_decoder_decoder_pkey_error_t *err) {
    (void)self; (void)params; (void)err; return true;
}

bool exports_openssl_decoder_decoder_method_decode_ctx_decode(
        exports_openssl_decoder_decoder_borrow_decode_ctx_t self,
        noop_list_u8_t *input,
        exports_openssl_decoder_decoder_key_selection_t selection,
        exports_openssl_decoder_decoder_list_decoded_object_t *ret,
        exports_openssl_decoder_decoder_pkey_error_t *err) {
    (void)self; (void)input; (void)selection; (void)err;
    ret->ptr = NULL; ret->len = 0; return true;
}

bool exports_openssl_decoder_decoder_method_decode_ctx_export_object(
        exports_openssl_decoder_decoder_borrow_decode_ctx_t self,
        exports_openssl_decoder_decoder_borrow_keydata_t obj,
        exports_openssl_decoder_decoder_list_ossl_param_t *ret,
        exports_openssl_decoder_decoder_pkey_error_t *err) {
    (void)self; (void)obj; (void)ret;
    ERR_NS(err); return false;
}
