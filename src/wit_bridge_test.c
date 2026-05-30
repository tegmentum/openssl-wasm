// Implementation of openssl:component/wit-bridge-test#sign-with-wit-bridge.
//
// Phase 3.5 verification: drives the wit-bridge chain end-to-end by
// calling the WIT imports directly. This bypasses EVP entirely --
// EVP_PKEY_fromdata + EVP_DigestSignInit_ex has too many moving parts
// (provider/keymgmt matching, OSSL_PARAM ctrl translation, etc.) for
// a Phase 3 first-light test. The full EVP integration lands in
// Phase 5 once Phase 6's set_pkcs11_key wrapper exists.
//
// What this DOES prove:
//   - openssl-wasm successfully imports the openssl:provider-abi WIT
//   - The composed provider component (simple-provider-adapter +
//     stub-key-backend) responds correctly to keymgmt + signature
//     calls
//   - The signature returned by signature.digest_sign verifies
//     against the stub's known SPKI -- i.e., the full Layer-1+2+3
//     chain produces cryptographically-valid signatures
//
// Sequence:
//   1. openssl_keymgmt_keymgmt_load(uri) -> Keydata
//   2. openssl_signature_signature_constructor_signature_context(NULL) -> SignatureContext
//   3. method.digest_sign_init(sigctx, mdname, keydata, [])
//   4. method.digest_sign(sigctx, tbs) -> signature bytes
//   5. drop everything

#include "bindings/openssl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_err(openssl_string_t *err, const char *msg) {
    openssl_string_dup(err, msg);
}

static void set_err_from_wit(openssl_string_t *err, const char *prefix,
                             openssl_pkey_pkey_pkey_error_t *we) {
    char buf[512];
    const char *tag_name;
    const char *detail = "";
    size_t detail_len = 0;
    switch (we->tag) {
    case OPENSSL_PKEY_PKEY_PKEY_ERROR_NOT_SUPPORTED:
        tag_name = "not-supported";
        detail = (const char *)we->val.not_supported.ptr;
        detail_len = we->val.not_supported.len;
        break;
    case OPENSSL_PKEY_PKEY_PKEY_ERROR_INVALID_ARGUMENT:
        tag_name = "invalid-argument";
        detail = (const char *)we->val.invalid_argument.ptr;
        detail_len = we->val.invalid_argument.len;
        break;
    case OPENSSL_PKEY_PKEY_PKEY_ERROR_INVALID_STATE:
        tag_name = "invalid-state";
        detail = (const char *)we->val.invalid_state.ptr;
        detail_len = we->val.invalid_state.len;
        break;
    case OPENSSL_PKEY_PKEY_PKEY_ERROR_INVALID_KEY:
        tag_name = "invalid-key";
        detail = (const char *)we->val.invalid_key.ptr;
        detail_len = we->val.invalid_key.len;
        break;
    case OPENSSL_PKEY_PKEY_PKEY_ERROR_BACKEND_ERROR:
        tag_name = "backend-error";
        detail = (const char *)we->val.backend_error.ptr;
        detail_len = we->val.backend_error.len;
        break;
    case OPENSSL_PKEY_PKEY_PKEY_ERROR_INTERNAL:
        tag_name = "internal";
        detail = (const char *)we->val.internal.ptr;
        detail_len = we->val.internal.len;
        break;
    default:
        tag_name = "unknown";
        break;
    }
    int n = snprintf(buf, sizeof(buf), "%s: %s", prefix, tag_name);
    if (detail_len > 0 && n < (int)sizeof(buf) - 2) {
        snprintf(buf + n, sizeof(buf) - n, " (%.*s)",
                 (int)detail_len, detail);
    }
    openssl_string_dup(err, buf);
    openssl_pkey_pkey_pkey_error_free(we);
}

bool exports_openssl_component_wit_bridge_test_sign_with_wit_bridge(
        openssl_string_t *uri,
        openssl_string_t *mdname,
        openssl_list_u8_t *tbs,
        openssl_list_u8_t *ret,
        openssl_string_t *err) {

    bool ok = false;

    // 1. keymgmt.load(uri) -> Keydata
    openssl_list_u8_t uri_bytes = { uri->ptr, uri->len };
    openssl_keymgmt_keymgmt_own_keydata_t kd;
    openssl_keymgmt_keymgmt_pkey_error_t kerr;
    bool got_keydata = false;
    if (!openssl_keymgmt_keymgmt_load(&uri_bytes, &kd, &kerr)) {
        set_err_from_wit(err, "keymgmt.load",
            (openssl_pkey_pkey_pkey_error_t *)&kerr);
        goto done;
    }
    got_keydata = true;

    // 2. signature-context constructor (no propq)
    openssl_signature_signature_own_signature_context_t sctx =
        openssl_signature_signature_constructor_signature_context(NULL);

    // 3. digest_sign_init(sigctx, mdname, keydata-borrow, [])
    openssl_string_t md_str;
    openssl_string_set(&md_str, ""); // placeholder, will overwrite
    md_str.ptr = mdname->ptr;
    md_str.len = mdname->len;
    openssl_signature_signature_borrow_keydata_t kd_borrow = {
        .__handle = kd.__handle,
    };
    openssl_signature_signature_borrow_signature_context_t sctx_borrow = {
        .__handle = sctx.__handle,
    };
    openssl_signature_signature_list_ossl_param_t no_params = { NULL, 0 };
    openssl_signature_signature_pkey_error_t serr;
    if (!openssl_signature_signature_method_signature_context_digest_sign_init(
            sctx_borrow, &md_str, kd_borrow, &no_params, &serr)) {
        set_err_from_wit(err, "signature.digest_sign_init",
            (openssl_pkey_pkey_pkey_error_t *)&serr);
        openssl_signature_signature_signature_context_drop_own(sctx);
        goto done;
    }

    // 4. digest_sign(sigctx, tbs) -> signature bytes
    openssl_list_u8_t tbs_in = { tbs->ptr, tbs->len };
    openssl_list_u8_t out;
    if (!openssl_signature_signature_method_signature_context_digest_sign(
            sctx_borrow, &tbs_in, &out, &serr)) {
        set_err_from_wit(err, "signature.digest_sign",
            (openssl_pkey_pkey_pkey_error_t *)&serr);
        openssl_signature_signature_signature_context_drop_own(sctx);
        goto done;
    }

    // 5. Hand the signature back; clean up.
    ret->ptr = out.ptr;
    ret->len = out.len;

    openssl_signature_signature_signature_context_drop_own(sctx);
    ok = true;

done:
    if (got_keydata) openssl_keymgmt_keymgmt_keydata_drop_own(kd);
    // Avoid unused-variable warning if helper isn't referenced.
    (void)set_err;
    return ok;
}
