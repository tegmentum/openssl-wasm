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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void emit_pkey_error(openssl_pkey_pkey_pkey_error_t *err);

// OSSL_PARAM marshallers shared with provider_wit.c. The encoder list
// type aliases the keymgmt one (both wrap openssl_pkey_pkey_ossl_param_t
// with identical struct layout), so we can build a keymgmt-typed list
// and reinterpret it for the encoder call.
extern void build_wit_params_full(
    const OSSL_PARAM params[],
    openssl_keymgmt_keymgmt_list_ossl_param_t *out);
extern bool fill_one_ossl_param(
    OSSL_PARAM *p, openssl_pkey_pkey_ossl_param_t *witp);

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

// OSSL_FUNC_ENCODER_GET_PARAMS — class-level (no ctx). The encoder's
// stable properties (output, structure, input) are already advertised
// via the OSSL_ALGORITHM property string at registration, so this has
// nothing instance-specific to report. Note: OpenSSL's encoder ABI
// has SETTABLE/SET_CTX_PARAMS but no GET_CTX_PARAMS counterpart — the
// per-instance encoder.get-params method on the WIT side stays
// unreachable from the C bridge until the upstream ABI grows that
// slot.
static int wit_encoder_get_params(OSSL_PARAM params[]) {
    if (params) {
        for (OSSL_PARAM *p = params; p->key; p++) p->return_size = 0;
    }
    return 1;
}

static int wit_encoder_set_ctx_params(void *ctx, const OSSL_PARAM params[]) {
    wit_encode_ctx_t *c = ctx;
    if (!c || c->marker != WIT_ENCODE_CTX_MARKER) return 0;

    // Reuse the keymgmt OSSL_PARAM[] → WIT list marshaller. The
    // encoder list type is a typedef alias of the keymgmt one
    // (same struct layout, same element type), so the cast is
    // memory-safe and avoids duplicating the marshaller.
    openssl_keymgmt_keymgmt_list_ossl_param_t wp_km;
    build_wit_params_full(params, &wp_km);
    openssl_encoder_encoder_list_ossl_param_t wp;
    wp.ptr = (openssl_encoder_encoder_ossl_param_t *)wp_km.ptr;
    wp.len = wp_km.len;

    openssl_encoder_encoder_pkey_error_t err;
    int ok = openssl_encoder_encoder_method_encode_ctx_set_ctx_params(
        encode_borrow(c), &wp, &err) ? 1 : 0;
    if (!ok) emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
    // Free through whichever typed accessor; the underlying alloc came
    // from build_wit_params_full's plain malloc, so the typed _free
    // walks the same chain.
    openssl_encoder_encoder_list_ossl_param_free(&wp);
    return ok;
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

// Defined in provider_wit.c; same wrapper for every WIT-managed key.
typedef struct wit_keydata {
    int32_t handle;
    bool    owned;
} wit_keydata_t;

static int wit_encoder_encode(
        void *ctx, OSSL_CORE_BIO *out,
        const void *obj_raw, const OSSL_PARAM obj_abstract[],
        int selection,
        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
    (void)obj_abstract; (void)pw_cb; (void)pw_cbarg;
    wit_encode_ctx_t *c = ctx;
    if (!c || c->marker != WIT_ENCODE_CTX_MARKER || !out) return 0;
    if (!obj_raw) return 0;  // abstract-object encode not implemented

    // OpenSSL only routes encoder calls to us when the key's keymgmt
    // (and propq) match this provider, so obj_raw is one of the
    // wit_keydata_t wrappers built in provider_wit.c's wit_keymgmt_new.
    const wit_keydata_t *w = obj_raw;
    openssl_encoder_encoder_borrow_keydata_t borrow = { .__handle = w->handle };

    uint8_t wit_sel = 0;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)       wit_sel |= 0x01;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)        wit_sel |= 0x02;
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) wit_sel |= 0x04;
    if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)  wit_sel |= 0x08;

    openssl_list_u8_t encoded = { NULL, 0 };
    openssl_encoder_encoder_pkey_error_t err;
    bool ok = openssl_encoder_encoder_method_encode_ctx_encode(
        encode_borrow(c), borrow, wit_sel, &encoded, &err);
    if (!ok) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }

    extern OSSL_FUNC_BIO_write_ex_fn *g_core_bio_write_ex;
    int rc = 1;
    if (encoded.len > 0) {
        if (!g_core_bio_write_ex) {
            rc = 0;  // provider_init failed to capture the upcall
        } else {
            size_t written = 0;
            if (!g_core_bio_write_ex(out, encoded.ptr, encoded.len, &written)
                || written != encoded.len) {
                rc = 0;
            }
        }
    }
    openssl_list_u8_free(&encoded);
    return rc;
}

// OSSL_FUNC_ENCODER_IMPORT_OBJECT: cross-provider encode entry point.
// OpenSSL calls this when the source EVP_PKEY's keymgmt isn't ours;
// the framework hands us the foreign key's exported public-key
// OSSL_PARAMs, we route them to encoder.import-object on the WIT
// side, and return a wit_keydata_t* that subsequent encode + free
// calls operate on.
static void *wit_encoder_import_object(void *ctx, int selection,
                                       const OSSL_PARAM params[]) {
    wit_encode_ctx_t *c = ctx;
    if (!c || c->marker != WIT_ENCODE_CTX_MARKER) return NULL;

    openssl_keymgmt_keymgmt_list_ossl_param_t wp_km;
    build_wit_params_full(params, &wp_km);
    openssl_encoder_encoder_list_ossl_param_t wp;
    wp.ptr = (openssl_encoder_encoder_ossl_param_t *)wp_km.ptr;
    wp.len = wp_km.len;

    openssl_encoder_encoder_own_keydata_t handle;
    openssl_encoder_encoder_pkey_error_t err;
    bool ok = openssl_encoder_encoder_method_encode_ctx_import_object(
        encode_borrow(c), (uint8_t)(selection & 0xff), &wp, &handle, &err);
    openssl_encoder_encoder_list_ossl_param_free(&wp);
    if (!ok) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return NULL;
    }
    wit_keydata_t *w = OPENSSL_malloc(sizeof(*w));
    if (!w) {
        // encoder own-keydata is a typedef of keymgmt own-keydata, so
        // its drop function lives under the keymgmt namespace.
        openssl_keymgmt_keymgmt_keydata_drop_own(handle);
        return NULL;
    }
    w->handle = handle.__handle;
    w->owned  = true;
    return w;
}

static void wit_encoder_free_object(void *obj) {
    wit_keydata_t *w = obj;
    if (!w) return;
    if (w->owned) {
        openssl_keymgmt_keymgmt_own_keydata_t h = { .__handle = w->handle };
        openssl_keymgmt_keymgmt_keydata_drop_own(h);
    }
    OPENSSL_free(w);
}

const OSSL_DISPATCH wit_encoder_dispatch[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,              (void (*)(void))wit_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX,             (void (*)(void))wit_encoder_freectx },
    { OSSL_FUNC_ENCODER_GET_PARAMS,          (void (*)(void))wit_encoder_get_params },
    { OSSL_FUNC_ENCODER_GETTABLE_PARAMS,     (void (*)(void))wit_encoder_gettable_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS,      (void (*)(void))wit_encoder_set_ctx_params },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))wit_encoder_settable_ctx_params },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,      (void (*)(void))wit_encoder_does_selection },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,       (void (*)(void))wit_encoder_import_object },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,         (void (*)(void))wit_encoder_free_object },
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
