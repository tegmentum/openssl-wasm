// OSSL_OP_DECODER bridge to openssl:decoder/decoder WIT.
//
// Symmetric to encoder_wit.c. The main op (decode) takes a BIO* in
// from OpenSSL, drains it into a byte buffer, hands the bytes to
// the WIT decode-ctx.decode(input, selection), and iterates the
// returned decoded-object list invoking OpenSSL's OSSL_CALLBACK
// once per object (with synthesised OSSL_OBJECT_PARAM_* attrs —
// same shape as store_wit.c's load callback).

#include "bindings/openssl.h"
#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <stdlib.h>
#include <string.h>

extern void emit_pkey_error(openssl_pkey_pkey_pkey_error_t *err);

#define WIT_MAX_DECODER_ALGOS 8
static char           g_decoder_name[WIT_MAX_DECODER_ALGOS][96];
static char           g_decoder_propq[WIT_MAX_DECODER_ALGOS][96];
static OSSL_ALGORITHM g_decoder_algos[WIT_MAX_DECODER_ALGOS + 1];
static bool           g_decoder_built = false;
extern const OSSL_DISPATCH wit_decoder_dispatch[];

typedef struct {
    uint32_t marker;                                  // 'WDEC' for sanity
    openssl_decoder_decoder_own_decode_ctx_t handle;
} wit_decode_ctx_t;

#define WIT_DECODE_CTX_MARKER 0x57444543u   // 'WDEC'

static inline openssl_decoder_decoder_borrow_decode_ctx_t
decode_borrow(wit_decode_ctx_t *c) {
    openssl_decoder_decoder_borrow_decode_ctx_t b;
    memcpy(&b, &c->handle, sizeof(b));
    return b;
}

// ---------------------------------------------------------------------------
// dispatch funcs
// ---------------------------------------------------------------------------

static void *wit_decoder_newctx(void *provctx) {
    (void)provctx;
    openssl_decoder_decoder_own_decode_ctx_t h =
        openssl_decoder_decoder_constructor_decode_ctx();
    wit_decode_ctx_t *c = OPENSSL_zalloc(sizeof(*c));
    if (!c) {
        openssl_decoder_decoder_decode_ctx_drop_own(h);
        return NULL;
    }
    c->marker = WIT_DECODE_CTX_MARKER;
    c->handle = h;
    return c;
}

static void wit_decoder_freectx(void *ctx) {
    wit_decode_ctx_t *c = ctx;
    if (!c || c->marker != WIT_DECODE_CTX_MARKER) return;
    openssl_decoder_decoder_decode_ctx_drop_own(c->handle);
    OPENSSL_free(c);
}

static const OSSL_PARAM *wit_decoder_gettable_params(void *provctx) {
    (void)provctx;
    static const OSSL_PARAM empty[] = { OSSL_PARAM_END };
    return empty;
}

static const OSSL_PARAM *wit_decoder_settable_ctx_params(void *provctx) {
    (void)provctx;
    static const OSSL_PARAM empty[] = { OSSL_PARAM_END };
    return empty;
}

static int wit_decoder_get_params(OSSL_PARAM params[]) {
    if (params) {
        for (OSSL_PARAM *p = params; p->key; p++) p->return_size = 0;
    }
    return 1;
}

static int wit_decoder_set_ctx_params(void *ctx, const OSSL_PARAM params[]) {
    wit_decode_ctx_t *c = ctx;
    if (!c || c->marker != WIT_DECODE_CTX_MARKER) return 0;
    (void)params;
    openssl_decoder_decoder_list_ossl_param_t empty = { NULL, 0 };
    openssl_decoder_decoder_pkey_error_t err;
    if (!openssl_decoder_decoder_method_decode_ctx_set_ctx_params(
            decode_borrow(c), &empty, &err)) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }
    return 1;
}

static int wit_decoder_does_selection(void *provctx, int selection) {
    (void)provctx;
    return openssl_decoder_decoder_does_selection((uint8_t)(selection & 0xff)) ? 1 : 0;
}

// Drain a BIO into a heap buffer. Caller frees with OPENSSL_free.
static unsigned char *bio_drain(OSSL_CORE_BIO *bio, size_t *out_len) {
    // OSSL_CORE_BIO uses the upcall table — but openssl-wasm's
    // bindings link against libssl directly, so BIO_* on a regular
    // BIO works. The conversion from OSSL_CORE_BIO* to BIO* is
    // identity in our build (no IPC boundary).
    BIO *b = (BIO *)bio;
    size_t cap = 4096, n = 0;
    unsigned char *buf = OPENSSL_malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (n + 4096 > cap) {
            cap *= 2;
            unsigned char *nb = OPENSSL_realloc(buf, cap);
            if (!nb) { OPENSSL_free(buf); return NULL; }
            buf = nb;
        }
        int r = BIO_read(b, buf + n, (int)(cap - n));
        if (r <= 0) break;
        n += (size_t)r;
    }
    *out_len = n;
    return buf;
}

static int wit_decoder_decode(
        void *ctx, OSSL_CORE_BIO *in, int selection,
        OSSL_CALLBACK *data_cb, void *data_cbarg,
        OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg) {
    (void)pw_cb; (void)pw_cbarg;
    wit_decode_ctx_t *c = ctx;
    if (!c || c->marker != WIT_DECODE_CTX_MARKER || !in || !data_cb) return 0;

    size_t in_len = 0;
    unsigned char *in_buf = bio_drain(in, &in_len);
    if (!in_buf) return 0;

    openssl_list_u8_t input = { in_buf, in_len };
    openssl_decoder_decoder_list_decoded_object_t out = { NULL, 0 };
    openssl_decoder_decoder_pkey_error_t err;

    bool ok = openssl_decoder_decoder_method_decode_ctx_decode(
        decode_borrow(c), &input, (uint8_t)(selection & 0xff), &out, &err);
    OPENSSL_free(in_buf);
    if (!ok) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }

    // Iterate the returned decoded-objects, invoking data_cb per
    // item. Synthesise OSSL_OBJECT_PARAM_* attrs same shape as
    // store_wit.c's load.
    int rc = 1;
    for (size_t i = 0; i < out.len; i++) {
        OSSL_PARAM params[4];
        int n = 0;
        int otype = 0;
        char data_type_buf[64];
        switch (out.ptr[i].tag) {
        case OPENSSL_DECODER_DECODER_DECODED_OBJECT_CERT:
            otype = OSSL_OBJECT_CERT;
            params[n++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &otype);
            params[n++] = OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_TYPE, (char *)"CERTIFICATE", 0);
            params[n++] = OSSL_PARAM_construct_octet_string(
                OSSL_OBJECT_PARAM_DATA,
                out.ptr[i].val.cert.ptr, out.ptr[i].val.cert.len);
            params[n] = OSSL_PARAM_construct_end();
            break;
        case OPENSSL_DECODER_DECODER_DECODED_OBJECT_CRL:
            otype = OSSL_OBJECT_CRL;
            params[n++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &otype);
            params[n++] = OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_TYPE, (char *)"X509 CRL", 0);
            params[n++] = OSSL_PARAM_construct_octet_string(
                OSSL_OBJECT_PARAM_DATA,
                out.ptr[i].val.crl.ptr, out.ptr[i].val.crl.len);
            params[n] = OSSL_PARAM_construct_end();
            break;
        case OPENSSL_DECODER_DECODER_DECODED_OBJECT_KEY:
            // The WIT decoded-object::key carries a keydata resource;
            // converting that into an OSSL_OBJECT_PARAM_REFERENCE +
            // OSSL_OBJECT_PARAM_DATA_TYPE byte stream requires
            // marshalling support that the Layer-2 adapter ships in
            // Phase 8 Session 3. For now skip key results.
            continue;
        case OPENSSL_DECODER_DECODER_DECODED_OBJECT_NAME:
            otype = OSSL_OBJECT_NAME;
            {
                size_t len = out.ptr[i].val.name.len < sizeof(data_type_buf) - 1
                    ? out.ptr[i].val.name.len : sizeof(data_type_buf) - 1;
                memcpy(data_type_buf, out.ptr[i].val.name.ptr, len);
                data_type_buf[len] = 0;
            }
            params[n++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &otype);
            params[n++] = OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA, data_type_buf, 0);
            params[n] = OSSL_PARAM_construct_end();
            break;
        default:
            continue;
        }
        if (!data_cb(params, data_cbarg)) {
            rc = 0;
            break;
        }
    }
    openssl_decoder_decoder_list_decoded_object_free(&out);
    return rc;
}

const OSSL_DISPATCH wit_decoder_dispatch[] = {
    { OSSL_FUNC_DECODER_NEWCTX,              (void (*)(void))wit_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX,             (void (*)(void))wit_decoder_freectx },
    { OSSL_FUNC_DECODER_GET_PARAMS,          (void (*)(void))wit_decoder_get_params },
    { OSSL_FUNC_DECODER_GETTABLE_PARAMS,     (void (*)(void))wit_decoder_gettable_params },
    { OSSL_FUNC_DECODER_SET_CTX_PARAMS,      (void (*)(void))wit_decoder_set_ctx_params },
    { OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, (void (*)(void))wit_decoder_settable_ctx_params },
    { OSSL_FUNC_DECODER_DOES_SELECTION,      (void (*)(void))wit_decoder_does_selection },
    { OSSL_FUNC_DECODER_DECODE,              (void (*)(void))wit_decoder_decode },
    { 0, NULL },
};

const OSSL_ALGORITHM *build_decoder_algos(void) {
    if (g_decoder_built)
        return g_decoder_algos[0].algorithm_names ? g_decoder_algos : NULL;

    openssl_provider_provider_tuple2_list_ossl_algorithm_bool_t tup = {
        { NULL, 0 }, false,
    };
    openssl_provider_provider_query_operation(
        OPENSSL_PKEY_PKEY_OPERATION_DECODER, &tup);

    if (tup.f0.len == 0) {
        openssl_provider_provider_list_ossl_algorithm_free(&tup.f0);
        g_decoder_built = true;
        return NULL;
    }

    size_t n = tup.f0.len < WIT_MAX_DECODER_ALGOS
        ? tup.f0.len : WIT_MAX_DECODER_ALGOS;
    for (size_t i = 0; i < n; i++) {
        openssl_provider_provider_ossl_algorithm_t *a = &tup.f0.ptr[i];
        {
            size_t len = a->algorithm_names.len < sizeof(g_decoder_name[i]) - 1
                ? a->algorithm_names.len : sizeof(g_decoder_name[i]) - 1;
            memcpy(g_decoder_name[i], a->algorithm_names.ptr, len);
            g_decoder_name[i][len] = 0;
        }
        {
            size_t len = a->property_definition.len < sizeof(g_decoder_propq[i]) - 1
                ? a->property_definition.len : sizeof(g_decoder_propq[i]) - 1;
            memcpy(g_decoder_propq[i], a->property_definition.ptr, len);
            g_decoder_propq[i][len] = 0;
        }
        g_decoder_algos[i].algorithm_names      = g_decoder_name[i];
        g_decoder_algos[i].property_definition  = g_decoder_propq[i];
        g_decoder_algos[i].implementation       = wit_decoder_dispatch;
        g_decoder_algos[i].algorithm_description = "wit-bridge decoder";
    }
    g_decoder_algos[n].algorithm_names      = NULL;
    g_decoder_algos[n].property_definition  = NULL;
    g_decoder_algos[n].implementation       = NULL;
    g_decoder_algos[n].algorithm_description = NULL;
    openssl_provider_provider_list_ossl_algorithm_free(&tup.f0);
    g_decoder_built = true;
    return g_decoder_algos;
}
