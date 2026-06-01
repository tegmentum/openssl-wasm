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

#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/store.h>

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

// ---------------------------------------------------------------------------
// digest-sign-via-evp-with-wit-bridge: EVP_DigestSign path (the path
// TLS actually uses). Phase 8a diagnostic for the open question from
// Phase 5.4. The EVP_PKEY_sign + manual-prehash variant above works;
// this variant should ALSO work after Phase 8a's expanded
// settable_ctx_params, since ctrl_params_translate.c was the
// suspected blocker.
// ---------------------------------------------------------------------------
bool exports_openssl_component_wit_bridge_test_digest_sign_via_evp_with_wit_bridge(
        openssl_string_t *uri,
        openssl_string_t *mdname,
        openssl_list_u8_t *tbs,
        openssl_list_u8_t *ret,
        openssl_string_t *err) {

    bool ok = false;
    OSSL_PROVIDER *def  = NULL;
    OSSL_PROVIDER *prov = NULL;
    EVP_PKEY_CTX  *pctx = NULL;
    EVP_PKEY      *pkey = NULL;
    EVP_MD_CTX    *mdctx = NULL;
    unsigned char *sig = NULL;
    char *uri_c = NULL, *md_c = NULL;

    uri_c = xmalloc(uri->len + 1);
    memcpy(uri_c, uri->ptr, uri->len); uri_c[uri->len] = 0;
    md_c  = xmalloc(mdname->len + 1);
    memcpy(md_c, mdname->ptr, mdname->len); md_c[mdname->len] = 0;

    def = OSSL_PROVIDER_load(NULL, "default");
    if (!def) { evp_err(err, "OSSL_PROVIDER_load(default)"); goto done; }
    prov = OSSL_PROVIDER_load(NULL, "wit-bridge");
    if (!prov) { evp_err(err, "OSSL_PROVIDER_load(wit-bridge)"); goto done; }

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

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) { openssl_string_dup(err, "EVP_MD_CTX_new"); goto done; }
    if (!EVP_DigestSignInit_ex(mdctx, NULL, md_c, NULL,
                               "?provider=wit-bridge", pkey, NULL)) {
        evp_err(err, "EVP_DigestSignInit_ex"); goto done;
    }

    size_t siglen = 0;
    if (!EVP_DigestSign(mdctx, NULL, &siglen, tbs->ptr, tbs->len)) {
        evp_err(err, "EVP_DigestSign sizing"); goto done;
    }
    sig = xmalloc(siglen);
    if (!EVP_DigestSign(mdctx, sig, &siglen, tbs->ptr, tbs->len)) {
        evp_err(err, "EVP_DigestSign final"); goto done;
    }

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
    if (def)  OSSL_PROVIDER_unload(def);
    return ok;
}

// ===========================================================================
// Phase 8: exercise OSSL_STORE through the wit-bridge chain end-to-end.
// Mirrors the path SSLContext.load_uri() takes from Python, but
// avoids needing a Python harness — the existing wit_bridge_test
// wasmtime tests already provide the pkcs11:util/util host stub.
// ===========================================================================
bool exports_openssl_component_wit_bridge_test_load_uri_test(
        openssl_string_t *uri,
        exports_openssl_component_wit_bridge_test_store_load_result_t *ret,
        openssl_string_t *err) {
    OSSL_PROVIDER *def = NULL, *prov = NULL;
    OSSL_STORE_CTX *sctx = NULL;
    bool ok = false;
    ret->cert_count = 0;
    ret->has_key    = false;
    ret->key_bits   = 0;

    char *uri_c = xmalloc(uri->len + 1);
    memcpy(uri_c, uri->ptr, uri->len); uri_c[uri->len] = 0;

    def  = OSSL_PROVIDER_load(NULL, "default");
    prov = OSSL_PROVIDER_load(NULL, "wit-bridge");
    if (!def || !prov) {
        const char *m = "OSSL_PROVIDER_load failed (default/wit-bridge)";
        err->ptr = (uint8_t *)xmalloc(strlen(m) + 1);
        memcpy(err->ptr, m, strlen(m));
        err->len = strlen(m);
        goto done;
    }

    sctx = OSSL_STORE_open(uri_c, NULL, NULL, NULL, NULL);
    if (!sctx) {
        const char *m = "OSSL_STORE_open failed (scheme not claimed by any provider?)";
        err->ptr = (uint8_t *)xmalloc(strlen(m) + 1);
        memcpy(err->ptr, m, strlen(m));
        err->len = strlen(m);
        goto done;
    }

    while (!OSSL_STORE_eof(sctx)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(sctx);
        if (!info) {
            if (OSSL_STORE_error(sctx)) break;
            continue;
        }
        switch (OSSL_STORE_INFO_get_type(info)) {
        case OSSL_STORE_INFO_CERT:
            ret->cert_count++;
            break;
        case OSSL_STORE_INFO_PKEY: {
            EVP_PKEY *k = OSSL_STORE_INFO_get1_PKEY(info);
            if (k && !ret->has_key) {
                ret->has_key  = true;
                ret->key_bits = (uint32_t)EVP_PKEY_get_bits(k);
            }
            EVP_PKEY_free(k);
            break;
        }
        case OSSL_STORE_INFO_PUBKEY: {
            EVP_PKEY *k = OSSL_STORE_INFO_get1_PUBKEY(info);
            if (k && !ret->has_key) {
                ret->has_key  = true;
                ret->key_bits = (uint32_t)EVP_PKEY_get_bits(k);
            }
            EVP_PKEY_free(k);
            break;
        }
        default: break;
        }
        OSSL_STORE_INFO_free(info);
    }
    ok = true;

done:
    if (sctx) OSSL_STORE_close(sctx);
    if (prov) OSSL_PROVIDER_unload(prov);
    if (def)  OSSL_PROVIDER_unload(def);
    free(uri_c);
    return ok;
}

// ===========================================================================
// Phase 8 follow-up (#296): exercise the OSSL_ENCODER chain through the
// wit-bridge. Build a wit-bridge-managed EVP_PKEY from `uri`, then run
// OSSL_ENCODER_to_data with SubjectPublicKeyInfo + DER. Returns the
// SPKI bytes the encoder produced.
// ===========================================================================
bool exports_openssl_component_wit_bridge_test_encode_spki_with_wit_bridge(
        openssl_string_t *uri,
        openssl_list_u8_t *ret,
        openssl_string_t *err) {
    bool ok = false;
    OSSL_PROVIDER *def = NULL, *prov = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    unsigned char *out = NULL;
    size_t out_len = 0;
    char *uri_c = NULL;

    uri_c = xmalloc(uri->len + 1);
    memcpy(uri_c, uri->ptr, uri->len); uri_c[uri->len] = 0;

    def  = OSSL_PROVIDER_load(NULL, "default");
    prov = OSSL_PROVIDER_load(NULL, "wit-bridge");
    if (!def || !prov) { evp_err(err, "OSSL_PROVIDER_load"); goto done; }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=wit-bridge");
    if (!pctx) { evp_err(err, "EVP_PKEY_CTX_new_from_name"); goto done; }
    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        evp_err(err, "EVP_PKEY_fromdata_init"); goto done;
    }
    OSSL_PARAM fd_params[] = {
        OSSL_PARAM_utf8_string("wit-bridge-uri", uri_c, uri->len),
        OSSL_PARAM_END,
    };
    // Phase 8 encode is PUBLIC_KEY only, but the keymgmt.load path
    // needs a selection that succeeds — KEYPAIR is what fromdata uses
    // elsewhere in this file, and the import_types_ex doesn't gate it.
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, fd_params) <= 0) {
        evp_err(err, "EVP_PKEY_fromdata"); goto done;
    }
    if (!pkey) { openssl_string_dup(err, "EVP_PKEY_fromdata: null pkey"); goto done; }

    ectx = OSSL_ENCODER_CTX_new_for_pkey(
        pkey, EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo",
        "provider=wit-bridge");
    if (!ectx) { evp_err(err, "OSSL_ENCODER_CTX_new_for_pkey"); goto done; }
    if (OSSL_ENCODER_CTX_get_num_encoders(ectx) == 0) {
        openssl_string_dup(err,
            "OSSL_ENCODER_CTX_new_for_pkey: no encoders matched "
            "(query-operation didn't advertise the SPKI encoder)");
        goto done;
    }
    if (OSSL_ENCODER_to_data(ectx, &out, &out_len) <= 0) {
        evp_err(err, "OSSL_ENCODER_to_data"); goto done;
    }
    if (!out || out_len == 0) {
        openssl_string_dup(err, "OSSL_ENCODER_to_data: empty output"); goto done;
    }

    ret->ptr = out; ret->len = out_len;
    out = NULL;  // ownership handed off
    ok = true;

done:
    OPENSSL_free(out);
    OSSL_ENCODER_CTX_free(ectx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    if (prov) OSSL_PROVIDER_unload(prov);
    if (def)  OSSL_PROVIDER_unload(def);
    free(uri_c);
    return ok;
}

// ===========================================================================
// #3 follow-up: cross-provider encode. Generate an EC key via the
// DEFAULT provider (its own keymgmt manages the key), then explicitly
// fetch the wit-bridge's SPKI encoder by property. OpenSSL's encoder
// framework recognises the keymgmt mismatch, calls our
// OSSL_FUNC_ENCODER_IMPORT_OBJECT to convert the default-provider
// keydata into a wit-bridge-managed handle, and encode runs on that.
// ===========================================================================
bool exports_openssl_component_wit_bridge_test_encode_spki_cross_provider(
        openssl_list_u8_t *ret,
        openssl_string_t *err) {
    bool ok = false;
    OSSL_PROVIDER *def = NULL, *prov = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *gctx = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    unsigned char *out = NULL;
    size_t out_len = 0;

    def  = OSSL_PROVIDER_load(NULL, "default");
    prov = OSSL_PROVIDER_load(NULL, "wit-bridge");
    if (!def || !prov) { evp_err(err, "OSSL_PROVIDER_load"); goto done; }

    // Generate a P-256 EC key on the DEFAULT provider. The resulting
    // EVP_PKEY's keymgmt is default's, not ours.
    gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=default");
    if (!gctx) { evp_err(err, "EVP_PKEY_CTX_new_from_name(EC,default)"); goto done; }
    if (EVP_PKEY_keygen_init(gctx) <= 0) { evp_err(err, "EVP_PKEY_keygen_init"); goto done; }
    OSSL_PARAM kp[] = {
        OSSL_PARAM_utf8_string("group", (char *)"P-256", 0),
        OSSL_PARAM_END,
    };
    if (EVP_PKEY_CTX_set_params(gctx, kp) <= 0) {
        evp_err(err, "EVP_PKEY_CTX_set_params(group)"); goto done;
    }
    if (EVP_PKEY_generate(gctx, &pkey) <= 0) {
        evp_err(err, "EVP_PKEY_generate"); goto done;
    }
    if (!pkey) { openssl_string_dup(err, "EVP_PKEY_generate: null pkey"); goto done; }

    // Force the wit-bridge encoder by propq, ignoring the (better-
    // matched) default-provider SPKI encoder. The framework will
    // detect the keymgmt mismatch and call our import_object.
    ectx = OSSL_ENCODER_CTX_new_for_pkey(
        pkey, EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo",
        "provider=wit-bridge");
    if (!ectx) { evp_err(err, "OSSL_ENCODER_CTX_new_for_pkey"); goto done; }
    if (OSSL_ENCODER_CTX_get_num_encoders(ectx) == 0) {
        openssl_string_dup(err,
            "OSSL_ENCODER_CTX_new_for_pkey: 0 wit-bridge encoders matched "
            "(import_object slot not advertised?)");
        goto done;
    }
    if (OSSL_ENCODER_to_data(ectx, &out, &out_len) <= 0) {
        evp_err(err, "OSSL_ENCODER_to_data"); goto done;
    }
    if (!out || out_len == 0) {
        openssl_string_dup(err, "OSSL_ENCODER_to_data: empty output"); goto done;
    }

    ret->ptr = out; ret->len = out_len;
    out = NULL;
    ok = true;

done:
    OPENSSL_free(out);
    OSSL_ENCODER_CTX_free(ectx);
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_free(pkey);
    if (prov) OSSL_PROVIDER_unload(prov);
    if (def)  OSSL_PROVIDER_unload(def);
    return ok;
}

// ===========================================================================
// #4 follow-up: decoder round-trip. Drives the WIT decoder directly
// (skipping OpenSSL's decoder framework — that integration is a
// separate ticket because OSSL_OBJECT_PARAM_REFERENCE plumbing has
// lifetime considerations). The flow:
//
//   1. decode_ctx.constructor()
//   2. decode(spki, PUBLIC_KEY) -> [Key(keydata)]
//   3. export_object(keydata)   -> [OsslParam] (group+pub for EC, n+e for RSA)
//   4. encode_ctx.constructor()
//   5. encoder.import_object(PUBLIC_KEY, params) -> Keydata'
//   6. encoder.encode(Keydata', PUBLIC_KEY) -> reassembled SPKI
//
// Successful round-trip means parse + export + re-import + re-encode
// all agree on the same param shape.
// ===========================================================================
bool exports_openssl_component_wit_bridge_test_decode_spki_round_trip_with_wit_bridge(
        openssl_list_u8_t *spki,
        openssl_list_u8_t *ret,
        openssl_string_t *err) {
    bool ok = false;
    openssl_decoder_decoder_own_decode_ctx_t dctx =
        openssl_decoder_decoder_constructor_decode_ctx();
    openssl_decoder_decoder_borrow_decode_ctx_t dctx_b = { .__handle = dctx.__handle };
    openssl_encoder_encoder_own_encode_ctx_t ectx =
        openssl_encoder_encoder_constructor_encode_ctx();
    openssl_encoder_encoder_borrow_encode_ctx_t ectx_b = { .__handle = ectx.__handle };

    openssl_list_u8_t input = { spki->ptr, spki->len };
    openssl_decoder_decoder_list_decoded_object_t decoded = { NULL, 0 };
    openssl_decoder_decoder_pkey_error_t dec_err;
    if (!openssl_decoder_decoder_method_decode_ctx_decode(
            dctx_b, &input, 0x02 /*PUBLIC_KEY*/, &decoded, &dec_err)) {
        set_err_from_wit(err, "decoder.decode",
            (openssl_pkey_pkey_pkey_error_t *)&dec_err);
        goto done;
    }
    if (decoded.len != 1 ||
        decoded.ptr[0].tag != OPENSSL_DECODER_DECODER_DECODED_OBJECT_KEY) {
        char buf[128];
        snprintf(buf, sizeof(buf),
            "decoder.decode: expected exactly one Key result, got len=%zu tag=%d",
            decoded.len, decoded.len > 0 ? (int)decoded.ptr[0].tag : -1);
        openssl_string_dup(err, buf);
        goto done;
    }
    openssl_decoder_decoder_borrow_keydata_t dec_kd_b = {
        .__handle = decoded.ptr[0].val.key.__handle,
    };
    openssl_decoder_decoder_list_ossl_param_t exported = { NULL, 0 };
    openssl_decoder_decoder_pkey_error_t exp_err;
    if (!openssl_decoder_decoder_method_decode_ctx_export_object(
            dctx_b, dec_kd_b, &exported, &exp_err)) {
        set_err_from_wit(err, "decoder.export-object",
            (openssl_pkey_pkey_pkey_error_t *)&exp_err);
        goto done;
    }

    // Hand the same param list to encoder.import-object (the encoder
    // list type is a typedef alias, so reinterpret-cast is safe).
    openssl_encoder_encoder_list_ossl_param_t imp_params;
    imp_params.ptr = (openssl_encoder_encoder_ossl_param_t *)exported.ptr;
    imp_params.len = exported.len;
    openssl_encoder_encoder_own_keydata_t imp_kd;
    openssl_encoder_encoder_pkey_error_t imp_err;
    if (!openssl_encoder_encoder_method_encode_ctx_import_object(
            ectx_b, 0x02 /*PUBLIC_KEY*/, &imp_params, &imp_kd, &imp_err)) {
        // Note: imp_params shares buffers with `exported`; the free
        // call below owns the cleanup.
        set_err_from_wit(err, "encoder.import-object",
            (openssl_pkey_pkey_pkey_error_t *)&imp_err);
        openssl_decoder_decoder_list_ossl_param_free(&exported);
        goto done;
    }
    openssl_decoder_decoder_list_ossl_param_free(&exported);

    openssl_encoder_encoder_borrow_keydata_t imp_kd_b = { .__handle = imp_kd.__handle };
    openssl_list_u8_t reassembled = { NULL, 0 };
    openssl_encoder_encoder_pkey_error_t enc_err;
    bool enc_ok = openssl_encoder_encoder_method_encode_ctx_encode(
        ectx_b, imp_kd_b, 0x02 /*PUBLIC_KEY*/, &reassembled, &enc_err);
    openssl_keymgmt_keymgmt_keydata_drop_own(imp_kd);
    if (!enc_ok) {
        set_err_from_wit(err, "encoder.encode",
            (openssl_pkey_pkey_pkey_error_t *)&enc_err);
        goto done;
    }
    ret->ptr = reassembled.ptr;
    ret->len = reassembled.len;
    ok = true;

done:
    openssl_decoder_decoder_list_decoded_object_free(&decoded);
    openssl_decoder_decoder_decode_ctx_drop_own(dctx);
    openssl_encoder_encoder_encode_ctx_drop_own(ectx);
    return ok;
}
