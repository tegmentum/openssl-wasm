// OSSL_OP_ENCODER bridge to openssl:encoder/encoder WIT.
//
// Lifecycle:
//   wit_encoder_newctx(provctx)         -> wraps openssl_encoder_encoder_constructor_encode_ctx
//                                          in a wit_encode_ctx_t with WIT_ENCODE_CTX_MARKER.
//   wit_encoder_set_ctx_params          -> forwards OSSL_PARAMs to the WIT ctx.
//   wit_encoder_does_selection          -> top-level WIT call (no ctx).
//   wit_encoder_encode                  -> ctx.encode(keydata, selection) -> bytes
//                                          written to OSSL_CORE_BIO *out via BIO_write.
//   wit_encoder_import_object           -> ctx.import-object(selection, params) -> keydata.
//   wit_encoder_freectx                 -> drops the WIT encode-ctx resource.
//
// The provider exports one OSSL_ALGORITHM per WIT-advertised encoder
// triple (input-type, output-type, structure) — queried at provider
// build time via provider.query-operation(operation::encoder).
//
// Limits / deferred:
//   - OSSL_FUNC_ENCODER_FREE_OBJECT is unreachable from the C side
//     (the import_object return is a WIT keydata that auto-drops).
//   - Passphrase callback for encrypted PEM is folded into set-ctx-
//     params via a "passphrase" octet-string param; not a separate
//     OSSL_PASSPHRASE_CALLBACK.

#include "bindings/openssl.h"
#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <stdlib.h>
#include <string.h>

extern void emit_pkey_error(openssl_pkey_pkey_pkey_error_t *err);

#define WIT_MAX_ENCODER_ALGOS 8
static char           g_encoder_name[WIT_MAX_ENCODER_ALGOS][96];
static char           g_encoder_propq[WIT_MAX_ENCODER_ALGOS][96];
static OSSL_ALGORITHM g_encoder_algos[WIT_MAX_ENCODER_ALGOS + 1];
static bool           g_encoder_built = false;
extern const OSSL_DISPATCH wit_encoder_dispatch[];

typedef struct {
    uint32_t marker;                                 // 'WENC' for sanity
    openssl_encoder_encoder_own_encode_ctx_t handle;
} wit_encode_ctx_t;

#define WIT_ENCODE_CTX_MARKER 0x57454e43u  // 'WENC'

static inline openssl_encoder_encoder_borrow_encode_ctx_t
encode_borrow(wit_encode_ctx_t *c) {
    openssl_encoder_encoder_borrow_encode_ctx_t b;
    memcpy(&b, &c->handle, sizeof(b));
    return b;
}

// ---------------------------------------------------------------------------
// dispatch funcs
// ---------------------------------------------------------------------------

static void *wit_encoder_newctx(void *provctx) {
    (void)provctx;
    openssl_encoder_encoder_own_encode_ctx_t h =
        openssl_encoder_encoder_constructor_encode_ctx();
    wit_encode_ctx_t *c = OPENSSL_zalloc(sizeof(*c));
    if (!c) {
        openssl_encoder_encoder_encode_ctx_drop_own(h);
        return NULL;
    }
    c->marker = WIT_ENCODE_CTX_MARKER;
    c->handle = h;
    return c;
}

static void wit_encoder_freectx(void *ctx) {
    wit_encode_ctx_t *c = ctx;
    if (!c || c->marker != WIT_ENCODE_CTX_MARKER) return;
    openssl_encoder_encoder_encode_ctx_drop_own(c->handle);
    OPENSSL_free(c);
}

static const OSSL_PARAM *wit_encoder_gettable_params(void *provctx) {
    (void)provctx;
    static const OSSL_PARAM empty[] = { OSSL_PARAM_END };
    return empty;
}

static const OSSL_PARAM *wit_encoder_settable_ctx_params(void *provctx) {
    (void)provctx;
    static const OSSL_PARAM empty[] = { OSSL_PARAM_END };
    return empty;
}

static int wit_encoder_get_params(OSSL_PARAM params[]) {
    // Phase 8 stub: zero return-size on every requested param so
    // OpenSSL knows the encoder has nothing to report. Real impl
    // forwards to ctx.get-params() and copies values across.
    if (params) {
        for (OSSL_PARAM *p = params; p->key; p++) p->return_size = 0;
    }
    return 1;
}

static int wit_encoder_set_ctx_params(void *ctx, const OSSL_PARAM params[]) {
    wit_encode_ctx_t *c = ctx;
    if (!c || c->marker != WIT_ENCODE_CTX_MARKER) return 0;
    // Forwarding OSSL_PARAM[] across WIT requires the same per-param
    // encoder we use for keymgmt set-params (Phase 8c+ work). For
    // now accept-and-ignore; the WIT side gets an empty list.
    (void)params;
    openssl_encoder_encoder_list_ossl_param_t empty = { NULL, 0 };
    openssl_encoder_encoder_pkey_error_t err;
    if (!openssl_encoder_encoder_method_encode_ctx_set_ctx_params(
            encode_borrow(c), &empty, &err)) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }
    return 1;
}

static int wit_encoder_does_selection(void *provctx, int selection) {
    (void)provctx;
    // does-selection is a top-level WIT method (no ctx state). The
    // adapter doesn't get a per-instance probe; we call the global
    // and let the backend answer.
    //
    // The WIT key-selection is a u8 bitflags; OpenSSL's int selection
    // packs the same bits (1=PRIVATE, 2=PUBLIC, 4=DOMAIN_PARAMS,
    // 8=OTHER_PARAMS, ... — see <openssl/core_dispatch.h>).
    return openssl_encoder_encoder_does_selection((uint8_t)(selection & 0xff)) ? 1 : 0;
}

static int wit_encoder_encode(
        void *ctx, OSSL_CORE_BIO *out,
        const void *obj_raw, const OSSL_PARAM obj_abstract[],
        int selection,
        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
    (void)obj_abstract; (void)pw_cb; (void)pw_cbarg;
    wit_encode_ctx_t *c = ctx;
    if (!c || c->marker != WIT_ENCODE_CTX_MARKER || !out) return 0;
    if (!obj_raw) {
        // obj_raw=NULL means "encode the abstract object in obj_abstract".
        // Phase 8: not implemented — most consumers pass a real keydata.
        return 0;
    }

    // The Layer-2 adapter is responsible for wrapping the C `obj_raw`
    // (= EVP_PKEY *) into a WIT keydata handle. simple-provider-adapter
    // stores the WIT handle inside the EVP_PKEY's provider-data; we
    // recover it here via a known accessor (Phase 8 Session 3 wires
    // this).
    //
    // Until then return 0 so OpenSSL falls back to its built-in
    // encoders.
    return 0;
}

const OSSL_DISPATCH wit_encoder_dispatch[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,              (void (*)(void))wit_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX,             (void (*)(void))wit_encoder_freectx },
    { OSSL_FUNC_ENCODER_GET_PARAMS,          (void (*)(void))wit_encoder_get_params },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS,     (void (*)(void))wit_encoder_gettable_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS,      (void (*)(void))wit_encoder_set_ctx_params },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))wit_encoder_settable_ctx_params },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,      (void (*)(void))wit_encoder_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,              (void (*)(void))wit_encoder_encode },
    { 0, NULL },
};

// ---------------------------------------------------------------------------
// algorithm table — queried from the WIT at provider build time.
// build_encoder_algos is called from provider_wit.c's
// wit_provider_query_operation when OpenSSL asks for OSSL_OP_ENCODER.
// ---------------------------------------------------------------------------

const OSSL_ALGORITHM *build_encoder_algos(void) {
    if (g_encoder_built)
        return g_encoder_algos[0].algorithm_names ? g_encoder_algos : NULL;

    openssl_provider_provider_tuple2_list_ossl_algorithm_bool_t tup = {
        { NULL, 0 }, false,
    };
    openssl_provider_provider_query_operation(
        OPENSSL_PKEY_PKEY_OPERATION_ENCODER, &tup);

    if (tup.f0.len == 0) {
        openssl_provider_provider_list_ossl_algorithm_free(&tup.f0);
        g_encoder_built = true;
        return NULL;
    }

    size_t n = tup.f0.len < WIT_MAX_ENCODER_ALGOS
        ? tup.f0.len : WIT_MAX_ENCODER_ALGOS;
    for (size_t i = 0; i < n; i++) {
        openssl_provider_provider_ossl_algorithm_t *a = &tup.f0.ptr[i];
        // strdup_first_alias is private to provider_wit.c; replicate inline.
        {
            size_t len = a->algorithm_names.len < sizeof(g_encoder_name[i]) - 1
                ? a->algorithm_names.len : sizeof(g_encoder_name[i]) - 1;
            memcpy(g_encoder_name[i], a->algorithm_names.ptr, len);
            g_encoder_name[i][len] = 0;
        }
        {
            size_t len = a->property_definition.len < sizeof(g_encoder_propq[i]) - 1
                ? a->property_definition.len : sizeof(g_encoder_propq[i]) - 1;
            memcpy(g_encoder_propq[i], a->property_definition.ptr, len);
            g_encoder_propq[i][len] = 0;
        }
        g_encoder_algos[i].algorithm_names      = g_encoder_name[i];
        g_encoder_algos[i].property_definition  = g_encoder_propq[i];
        g_encoder_algos[i].implementation       = wit_encoder_dispatch;
        g_encoder_algos[i].algorithm_description = "wit-bridge encoder";
    }
    g_encoder_algos[n].algorithm_names      = NULL;
    g_encoder_algos[n].property_definition  = NULL;
    g_encoder_algos[n].implementation       = NULL;
    g_encoder_algos[n].algorithm_description = NULL;
    openssl_provider_provider_list_ossl_algorithm_free(&tup.f0);
    g_encoder_built = true;
    return g_encoder_algos;
}
