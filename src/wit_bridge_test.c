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
#include "include/support.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/provider.h>

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

// ---------------------------------------------------------------------------
// sign-via-evp-with-wit-bridge: drive the same chain via OpenSSL's
// EVP layer. Constructs an EVP_PKEY backed by the wit-bridge keymgmt
// via EVP_PKEY_fromdata (with a custom "wit-bridge-uri" OSSL_PARAM
// that the simple-provider-adapter's keymgmt.import recognizes),
// then runs EVP_DigestSign on it.
//
// If this works, SSL_CTX_use_PrivateKey with the same EVP_PKEY will
// work too -- TLS handshake follows.
// ---------------------------------------------------------------------------

static void evp_err(openssl_string_t *err, const char *prefix) {
    char accum[2048];
    int n = snprintf(accum, sizeof(accum), "%s", prefix);
    unsigned long e;
    int count = 0;
    while ((e = ERR_get_error()) != 0 && count < 10) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        n += snprintf(accum + n,
                      n < (int)sizeof(accum) ? (int)sizeof(accum) - n : 0,
                      " | %s", buf);
        count++;
    }
    if (count == 0) {
        snprintf(accum + n,
                 n < (int)sizeof(accum) ? (int)sizeof(accum) - n : 0,
                 " (no error queue entry)");
    }
    openssl_string_dup(err, accum);
}

bool exports_openssl_component_wit_bridge_test_sign_via_evp_with_wit_bridge(
        openssl_string_t *uri,
        openssl_string_t *mdname,
        openssl_list_u8_t *tbs,
        openssl_list_u8_t *ret,
        openssl_string_t *err) {

    bool ok = false;
    OSSL_PROVIDER *prov = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char *sig = NULL;
    char *uri_c = NULL, *md_c = NULL;

    uri_c = xmalloc(uri->len + 1);
    memcpy(uri_c, uri->ptr, uri->len); uri_c[uri->len] = 0;
    md_c  = xmalloc(mdname->len + 1);
    memcpy(md_c, mdname->ptr, mdname->len); md_c[mdname->len] = 0;

    // Loading wit-bridge disables the default-provider auto-load.
    // Reload the default explicitly so EVP_MD_fetch("SHA2-256") and
    // friends still find their implementations.
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    if (!def) { evp_err(err, "OSSL_PROVIDER_load(default)"); goto done; }
    prov = OSSL_PROVIDER_load(NULL, "wit-bridge");
    if (!prov) {
        OSSL_PROVIDER_unload(def);
        evp_err(err, "OSSL_PROVIDER_load(wit-bridge)"); goto done;
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=wit-bridge");
    if (!pctx) { evp_err(err, "EVP_PKEY_CTX_new_from_name"); goto done; }
    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        evp_err(err, "EVP_PKEY_fromdata_init"); goto done;
    }
    OSSL_PARAM fd_params[] = {
        OSSL_PARAM_utf8_string("wit-bridge-uri", uri_c, uri->len),
        OSSL_PARAM_END,
    };
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, fd_params) <= 0) {
        evp_err(err, "EVP_PKEY_fromdata"); goto done;
    }
    if (!pkey) { openssl_string_dup(err, "EVP_PKEY_fromdata: null pkey"); goto done; }

    // Use EVP_PKEY_sign (raw, no digest lookup) instead of
    // EVP_DigestSign -- avoids the propq mismatch between keymgmt
    // fetch and digest fetch that trips m_sigver in the
    // EVP_DigestSign path. Hash the message ourselves with SHA-256
    // first; CKM_ECDSA expects a pre-hashed input.
    EVP_MD *md = EVP_MD_fetch(NULL, md_c, NULL);
    if (!md) { evp_err(err, "EVP_MD_fetch"); goto done; }
    unsigned char prehash[64];
    unsigned int  prehash_len = 0;
    if (!EVP_Digest(tbs->ptr, tbs->len, prehash, &prehash_len, md, NULL)) {
        EVP_MD_free(md);
        evp_err(err, "EVP_Digest"); goto done;
    }
    EVP_MD_free(md);

    EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey,
                                                    "provider=wit-bridge");
    if (!sctx) { evp_err(err, "EVP_PKEY_CTX_new_from_pkey"); goto done; }
    if (EVP_PKEY_sign_init(sctx) <= 0) {
        EVP_PKEY_CTX_free(sctx);
        evp_err(err, "EVP_PKEY_sign_init"); goto done;
    }
    size_t siglen = 0;
    if (EVP_PKEY_sign(sctx, NULL, &siglen, prehash, prehash_len) <= 0) {
        EVP_PKEY_CTX_free(sctx);
        evp_err(err, "EVP_PKEY_sign sizing"); goto done;
    }
    sig = xmalloc(siglen);
    if (EVP_PKEY_sign(sctx, sig, &siglen, prehash, prehash_len) <= 0) {
        EVP_PKEY_CTX_free(sctx);
        evp_err(err, "EVP_PKEY_sign final"); goto done;
    }
    EVP_PKEY_CTX_free(sctx);
    (void)mdctx;  // unused in this variant

    ret->ptr = sig; ret->len = siglen;
    sig = NULL;
    ok = true;

done:
    free(sig);
    free(uri_c);
    free(md_c);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    if (prov) OSSL_PROVIDER_unload(prov);
    return ok;
}
