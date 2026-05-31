// OSSL_OP_STORE bridge to openssl:store/store WIT.
//
// Lifecycle:
//   wit_store_open(uri)           -> wraps openssl_store_store_constructor_loader
//                                    in a wit_loader_t and returns it as void *loaderctx.
//   wit_store_set_ctx_params      -> forwards OSSL_PARAMs to the WIT loader.
//   wit_store_load                -> polls loader.load() once; if it yields a
//                                    store-object, we synthesise the matching
//                                    OSSL_PARAM[] and invoke OpenSSL's object_cb.
//                                    eof() is checked between calls so OpenSSL
//                                    can stop iterating.
//   wit_store_eof                 -> mirrors loader.eof().
//   wit_store_close               -> drops the WIT loader handle and frees
//                                    the wit_loader_t.
//
// The provider exports one OSSL_ALGORITHM per supported URI scheme
// (queried from the WIT via supported-schemes()), all sharing the
// dispatch table below. The scheme name = the algorithm name; the
// scheme-to-loader resolution happens inside the backend.
//
// Limits / deferred:
//   - OSSL_FUNC_STORE_ATTACH (BIO-based load) is not implemented.
//   - OSSL_FUNC_STORE_OPEN_EX (open + params + pw_cb in one call) is
//     not implemented; callers use OPEN + SET_CTX_PARAMS instead.
//   - OSSL_FUNC_STORE_EXPORT_OBJECT (CLI-only) is not implemented.
//   - Passphrase callback is not used; URIs carry pin-value= (RFC 7512).

#include "bindings/openssl.h"
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/store.h>
#include <stdlib.h>
#include <string.h>

// Helpers from provider_wit.c.
extern void emit_pkey_error(openssl_pkey_pkey_pkey_error_t *err);

#define WIT_MAX_STORE_SCHEMES 4
static char           g_store_scheme[WIT_MAX_STORE_SCHEMES][64];
static OSSL_ALGORITHM g_store_algos[WIT_MAX_STORE_SCHEMES + 1];
static bool           g_store_built = false;
extern const OSSL_DISPATCH wit_store_dispatch[];

// Loader-context wrapper: holds the WIT loader handle. wit_store_open
// returns a `wit_loader_t *` as the opaque void *loaderctx and every
// other dispatch func borrows it back through the same pointer.
typedef struct {
    uint32_t marker;                      // 'WSTR' for sanity
    openssl_store_store_own_loader_t handle;
} wit_loader_t;

#define WIT_LOADER_MARKER 0x57535452u  // 'WSTR'

static inline openssl_store_store_borrow_loader_t
loader_borrow(wit_loader_t *l) {
    // wit-bindgen-c borrow handles are just the same word as the own
    // handle; the type layer enforces lifetime, not the bits.
    openssl_store_store_borrow_loader_t b;
    memcpy(&b, &l->handle, sizeof(b));
    return b;
}

// ---------------------------------------------------------------------------
// open / close
// ---------------------------------------------------------------------------

static void *wit_store_open(void *provctx, const char *uri) {
    (void)provctx;
    if (uri == NULL) return NULL;
    openssl_string_t s = { .ptr = (uint8_t *)uri, .len = strlen(uri) };
    openssl_store_store_own_loader_t h = openssl_store_store_constructor_loader(&s);
    wit_loader_t *l = OPENSSL_zalloc(sizeof(*l));
    if (l == NULL) {
        openssl_store_store_loader_drop_own(h);
        return NULL;
    }
    l->marker = WIT_LOADER_MARKER;
    l->handle = h;
    return l;
}

static int wit_store_close(void *loaderctx) {
    wit_loader_t *l = loaderctx;
    if (l == NULL || l->marker != WIT_LOADER_MARKER) return 0;
    openssl_store_store_loader_drop_own(l->handle);
    OPENSSL_free(l);
    return 1;
}

// ---------------------------------------------------------------------------
// settable / set ctx params
// ---------------------------------------------------------------------------

static const OSSL_PARAM *wit_store_settable_ctx_params(void *provctx) {
    (void)provctx;
    // The WIT exposes settable-ctx-params() but we don't currently
    // forward it; OpenSSL accepts any params and the WIT loader
    // is free to ignore unknown ones in set-ctx-params. Empty list
    // signals "no specific params advertised" which is valid.
    static const OSSL_PARAM empty[] = { OSSL_PARAM_END };
    return empty;
}

static int wit_store_set_ctx_params(void *loaderctx, const OSSL_PARAM params[]) {
    wit_loader_t *l = loaderctx;
    if (l == NULL || l->marker != WIT_LOADER_MARKER) return 0;
    // For MVP we accept-and-ignore. Forwarding OSSL_PARAM[] through
    // the WIT requires per-param re-encoding (the same machinery as
    // keymgmt set-params); add when the first caller actually sets a
    // store-side param that the backend needs to honor.
    (void)params;
    openssl_store_store_list_ossl_param_t empty = { NULL, 0 };
    openssl_store_store_pkey_error_t err;
    if (!openssl_store_store_method_loader_set_ctx_params(loader_borrow(l), &empty, &err)) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }
    return 1;
}

// ---------------------------------------------------------------------------
// load / eof
// ---------------------------------------------------------------------------

// Map an openssl_string_t (not NUL-terminated) into a stable temp
// buffer for use as a C string. dst must be at least len+1 bytes.
static void copy_to_cstr(char *dst, size_t dst_sz, const openssl_string_t *s) {
    size_t n = s->len < dst_sz - 1 ? s->len : dst_sz - 1;
    memcpy(dst, s->ptr, n);
    dst[n] = 0;
}

static int wit_store_load(void *loaderctx,
                          OSSL_CALLBACK *object_cb, void *object_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
    (void)pw_cb; (void)pw_cbarg;
    wit_loader_t *l = loaderctx;
    if (l == NULL || l->marker != WIT_LOADER_MARKER || object_cb == NULL) return 0;

    openssl_store_store_option_store_object_t ret = { false, {0} };
    openssl_store_store_pkey_error_t err;
    if (!openssl_store_store_method_loader_load(loader_borrow(l), &ret, &err)) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }
    if (!ret.is_some) {
        // No object this round. OpenSSL polls eof() separately to know
        // whether to keep looping.
        return 1;
    }

    int rc = 0;
    char data_type_buf[64];
    OSSL_PARAM params[5];
    int n = 0;

    switch (ret.val.tag) {
    case OPENSSL_STORE_STORE_STORE_OBJECT_CERT: {
        int otype = OSSL_OBJECT_CERT;
        params[n++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &otype);
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_TYPE, (char *)"CERTIFICATE", 0);
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_DATA,
            ret.val.val.cert.ptr, ret.val.val.cert.len);
        params[n] = OSSL_PARAM_construct_end();
        rc = object_cb(params, object_cbarg);
        break;
    }
    case OPENSSL_STORE_STORE_STORE_OBJECT_CRL: {
        int otype = OSSL_OBJECT_CRL;
        params[n++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &otype);
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_TYPE, (char *)"X509 CRL", 0);
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_DATA,
            ret.val.val.crl.ptr, ret.val.val.crl.len);
        params[n] = OSSL_PARAM_construct_end();
        rc = object_cb(params, object_cbarg);
        break;
    }
    case OPENSSL_STORE_STORE_STORE_OBJECT_KEY_REFERENCE: {
        // tuple<string, list<u8>>  --  (data-type, reference)
        int otype = OSSL_OBJECT_PKEY;
        copy_to_cstr(data_type_buf, sizeof(data_type_buf),
                     &ret.val.val.key_reference.f0);
        params[n++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &otype);
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_TYPE, data_type_buf, 0);
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE,
            ret.val.val.key_reference.f1.ptr,
            ret.val.val.key_reference.f1.len);
        params[n] = OSSL_PARAM_construct_end();
        rc = object_cb(params, object_cbarg);
        break;
    }
    case OPENSSL_STORE_STORE_STORE_OBJECT_NAME: {
        int otype = OSSL_OBJECT_NAME;
        copy_to_cstr(data_type_buf, sizeof(data_type_buf), &ret.val.val.name);
        params[n++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &otype);
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA, data_type_buf, 0);
        params[n] = OSSL_PARAM_construct_end();
        rc = object_cb(params, object_cbarg);
        break;
    }
    default:
        rc = 0;
        break;
    }

    openssl_store_store_option_store_object_free(&ret);
    return rc;
}

static int wit_store_eof(void *loaderctx) {
    wit_loader_t *l = loaderctx;
    if (l == NULL || l->marker != WIT_LOADER_MARKER) return 1;
    return openssl_store_store_method_loader_eof(loader_borrow(l)) ? 1 : 0;
}

// ---------------------------------------------------------------------------
// top-level: delete
// ---------------------------------------------------------------------------

static int wit_store_delete(void *provctx, const char *uri,
                            const OSSL_PARAM params[],
                            OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
    (void)provctx; (void)params; (void)pw_cb; (void)pw_cbarg;
    if (uri == NULL) return 0;
    openssl_string_t s = { .ptr = (uint8_t *)uri, .len = strlen(uri) };
    openssl_store_store_pkey_error_t err;
    if (!openssl_store_store_delete(&s, &err)) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Dispatch table -- one per scheme; we hand out the same table for
// every algorithm entry because the scheme name is the join key, not
// the dispatch.
// ---------------------------------------------------------------------------

const OSSL_DISPATCH wit_store_dispatch[] = {
    { OSSL_FUNC_STORE_OPEN,                (void (*)(void))wit_store_open },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void))wit_store_settable_ctx_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS,      (void (*)(void))wit_store_set_ctx_params },
    { OSSL_FUNC_STORE_LOAD,                (void (*)(void))wit_store_load },
    { OSSL_FUNC_STORE_EOF,                 (void (*)(void))wit_store_eof },
    { OSSL_FUNC_STORE_CLOSE,               (void (*)(void))wit_store_close },
    { OSSL_FUNC_STORE_DELETE,              (void (*)(void))wit_store_delete },
    { 0, NULL },
};

// ---------------------------------------------------------------------------
// Algorithm table — one entry per scheme advertised by the WIT.
// Called from provider_wit.c's wit_provider_query_operation when
// OpenSSL queries OSSL_OP_STORE.
// ---------------------------------------------------------------------------

const OSSL_ALGORITHM *build_store_algos(void) {
    if (g_store_built) return g_store_algos[0].algorithm_names != NULL ? g_store_algos : NULL;
    openssl_list_string_t schemes = { NULL, 0 };
    openssl_store_store_supported_schemes(&schemes);
    if (schemes.len == 0) {
        openssl_list_string_free(&schemes);
        g_store_built = true;
        return NULL;
    }
    size_t n = schemes.len < WIT_MAX_STORE_SCHEMES ? schemes.len : WIT_MAX_STORE_SCHEMES;
    for (size_t i = 0; i < n; i++) {
        copy_to_cstr(g_store_scheme[i], sizeof(g_store_scheme[i]), &schemes.ptr[i]);
        g_store_algos[i].algorithm_names     = g_store_scheme[i];
        g_store_algos[i].property_definition = "provider=wit-bridge";
        g_store_algos[i].implementation      = wit_store_dispatch;
        g_store_algos[i].algorithm_description = "wit-bridge store loader";
    }
    g_store_algos[n].algorithm_names     = NULL;
    g_store_algos[n].property_definition = NULL;
    g_store_algos[n].implementation      = NULL;
    g_store_algos[n].algorithm_description = NULL;
    openssl_list_string_free(&schemes);
    g_store_built = true;
    return g_store_algos;
}
