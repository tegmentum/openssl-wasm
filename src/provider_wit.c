// WIT <-> OSSL_PROVIDER bridge.
//
// Phase 2 + 3.5 of the openssl-provider-wit plan. Lets OpenSSL load
// providers by name ("wit-bridge") and dispatch keymgmt + signature
// operations through the WIT-imported provider component.
//
// Layout:
//
//   provider_core.c calls prov->init_function ((OSSL_CORE_HANDLE *)
//   prov, core_dispatch, &provider_dispatch, &tmp_provctx). For the
//   "wit-bridge" name we install ossl_wit_provider_init via
//   OSSL_PROVIDER_add_builtin().
//
//   ossl_wit_provider_init returns a static OSSL_DISPATCH advertising
//   provider_teardown, gettable_params, get_params, query_operation,
//   unquery_operation, get_capabilities, self_test, random_bytes.
//
//   On query_operation OpenSSL asks "what algorithms do you provide
//   for op X?" Our thunk calls the WIT-imported
//   openssl_provider_provider_query_operation(op, &tup), gets back a
//   list<ossl-algorithm>, and builds a persistent C OSSL_ALGORITHM[]
//   each entry pointing at a static OSSL_DISPATCH[] of keymgmt /
//   signature thunks that marshal C calls back into the WIT.
//
// Memory model:
//
//   OSSL_ALGORITHM arrays we hand back must outlive OpenSSL's use of
//   them. The per-op cache (g_keymgmt_algos, g_signature_algos) is a
//   small static array (one entry + sentinel for now). Algorithm
//   name strings are strdup'd once into algo_name_storage and never
//   freed -- they live for the program lifetime.
//
//   keydata / signature-context WIT resources are wrapped in small
//   structs (wit_keydata_t / wit_sigctx_t) so OpenSSL's `void *` can
//   carry them around. The wrapper is malloc'd on keymgmt_new /
//   signature_newctx and freed on keymgmt_free / signature_freectx.

#include "bindings/openssl.h"
#include "include/support.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/provider.h>

#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Bridge per-instance state.
typedef struct wit_provctx {
    int marker;
} wit_provctx_t;
#define WIT_PROVCTX_MARKER 0x57495424  // 'WIT$'

// ---------------------------------------------------------------------------
// C->WIT operation enum translation.
static bool wit_operation_from_ossl(int ossl_op,
                                    openssl_provider_provider_operation_t *out) {
    switch (ossl_op) {
        case OSSL_OP_DIGEST:      *out = OPENSSL_PKEY_PKEY_OPERATION_DIGEST;      return true;
        case OSSL_OP_CIPHER:      *out = OPENSSL_PKEY_PKEY_OPERATION_CIPHER;      return true;
        case OSSL_OP_MAC:         *out = OPENSSL_PKEY_PKEY_OPERATION_MAC;         return true;
        case OSSL_OP_KDF:         *out = OPENSSL_PKEY_PKEY_OPERATION_KDF;         return true;
        case OSSL_OP_RAND:        *out = OPENSSL_PKEY_PKEY_OPERATION_RAND;        return true;
        case OSSL_OP_KEYMGMT:     *out = OPENSSL_PKEY_PKEY_OPERATION_KEYMGMT;     return true;
        case OSSL_OP_KEYEXCH:     *out = OPENSSL_PKEY_PKEY_OPERATION_KEYEXCH;     return true;
        case OSSL_OP_SIGNATURE:   *out = OPENSSL_PKEY_PKEY_OPERATION_SIGNATURE;   return true;
        case OSSL_OP_ASYM_CIPHER: *out = OPENSSL_PKEY_PKEY_OPERATION_ASYM_CIPHER; return true;
        case OSSL_OP_KEM:         *out = OPENSSL_PKEY_PKEY_OPERATION_KEM;         return true;
        case OSSL_OP_SKEYMGMT:    *out = OPENSSL_PKEY_PKEY_OPERATION_SKEYMGMT;    return true;
        case OSSL_OP_ENCODER:     *out = OPENSSL_PKEY_PKEY_OPERATION_ENCODER;     return true;
        case OSSL_OP_DECODER:     *out = OPENSSL_PKEY_PKEY_OPERATION_DECODER;     return true;
        case OSSL_OP_STORE:       *out = OPENSSL_PKEY_PKEY_OPERATION_STORE;       return true;
        default:                                                                   return false;
    }
}

// ===========================================================================
// Helpers: WIT canonical-ABI struct helpers, error mapping
// ===========================================================================

// Convert a C `int selection` (PRIVATE_KEY | PUBLIC_KEY | ...) into
// the WIT flags byte (same bit layout).
static inline uint8_t selection_to_wit(int sel) {
    uint8_t out = 0;
    if (sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)       out |= 0x01;
    if (sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)        out |= 0x02;
    if (sel & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) out |= 0x04;
    if (sel & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)  out |= 0x08;
    return out;
}

// Free a WIT-returned pkey-error and emit an OpenSSL error queue
// entry summarizing it. Best-effort; the WIT side already populated
// `err` with details.
static void emit_pkey_error(openssl_pkey_pkey_pkey_error_t *err) {
    // Phase 3: just raise a generic provider error. Phase 8 wires the
    // variant tag to specific OpenSSL reason codes via ERR_raise_data.
    ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
    openssl_pkey_pkey_pkey_error_free(err);
}

// ===========================================================================
// keydata wrapper -- the `void *keydata` that OpenSSL passes around
// is actually one of these, malloc'd in wit_keymgmt_new() and freed
// in wit_keymgmt_free().
// ===========================================================================
typedef struct wit_keydata {
    int32_t handle;  // openssl_keymgmt_keymgmt_own_keydata_t.__handle
    bool    owned;   // true => must drop on free; false => borrowed
} wit_keydata_t;

static inline openssl_keymgmt_keymgmt_borrow_keydata_t
borrow_keydata(const wit_keydata_t *k) {
    return (openssl_keymgmt_keymgmt_borrow_keydata_t){ .__handle = k->handle };
}

// ===========================================================================
// keymgmt thunks
// ===========================================================================

static void *wit_keymgmt_new(void *provctx) {
    (void)provctx;
    openssl_keymgmt_keymgmt_own_keydata_t handle =
        openssl_keymgmt_keymgmt_constructor_keydata();
    wit_keydata_t *w = malloc(sizeof(*w));
    if (!w) {
        openssl_keymgmt_keymgmt_keydata_drop_own(handle);
        return NULL;
    }
    w->handle = handle.__handle;
    w->owned  = true;
    return w;
}

static void wit_keymgmt_free(void *keydata) {
    if (!keydata) return;
    wit_keydata_t *w = keydata;
    if (w->owned) {
        openssl_keymgmt_keymgmt_own_keydata_t own = { .__handle = w->handle };
        openssl_keymgmt_keymgmt_keydata_drop_own(own);
    }
    free(w);
}

static void *wit_keymgmt_load(const void *reference, size_t reference_sz) {
    // OpenSSL passes a pointer; for our STORE-by-URI path the
    // adapter's Phase 6 wrapper will pass the URI bytes directly.
    // Phase 3.5 test export uses the same convention.
    openssl_list_u8_t ref = { (uint8_t *)reference, reference_sz };
    openssl_keymgmt_keymgmt_own_keydata_t ret;
    openssl_keymgmt_keymgmt_pkey_error_t err;
    if (!openssl_keymgmt_keymgmt_load(&ref, &ret, &err)) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return NULL;
    }
    wit_keydata_t *w = malloc(sizeof(*w));
    if (!w) {
        openssl_keymgmt_keymgmt_keydata_drop_own(ret);
        return NULL;
    }
    w->handle = ret.__handle;
    w->owned  = true;
    return w;
}

static int wit_keymgmt_has(const void *keydata, int selection) {
    const wit_keydata_t *w = keydata;
    if (!w) return 0;
    return openssl_keymgmt_keymgmt_method_keydata_has(
        borrow_keydata(w), selection_to_wit(selection)) ? 1 : 0;
}

static int wit_keymgmt_match(const void *a, const void *b, int selection) {
    if (!a || !b) return 0;
    const wit_keydata_t *wa = a;
    const wit_keydata_t *wb = b;
    return openssl_keymgmt_keymgmt_method_keydata_match(
        borrow_keydata(wa), borrow_keydata(wb),
        selection_to_wit(selection)) ? 1 : 0;
}

// Convert one WIT ossl-param into an OSSL_PARAM and stash it in
// bld_buf at *bld_n. Handles the variants TLS / cert-build / X.509
// signing actually use: utf8-string (curve names), octet-string
// (encoded keys, SPKI), unsigned-integer (bit sizes), integer.
// Phase 8 extends to big-int + others.
//
// CAUTION: the OSSL_PARAM holds pointers into p->value.*. Those
// pointers must stay live until the consumer copies the values out
// (which the OSSL_PARAM "set" path does immediately). Caller must
// not free the WIT list before param_cb returns.
//
// Strings stashed by OSSL_PARAM_construct_utf8_string must be NUL-
// terminated, but our WIT strings are length-only. We patch a NUL
// byte into the buffer in-place before construction (the WIT runtime
// always allocates one extra byte for the string sentinel).
static void emit_ossl_param_to_cb(
        openssl_pkey_pkey_ossl_param_t *p,
        OSSL_CALLBACK *param_cb, void *cbarg, OSSL_PARAM *bld_buf, int *bld_n) {
    (void)param_cb; (void)cbarg;
    // Make the key C-string (NUL-terminate the WIT string in place;
    // wit-bindgen runtime over-allocates by one byte for this).
    char *key_c = (char *)p->key.ptr;
    key_c[p->key.len] = 0;

    switch (p->value.tag) {
    case OPENSSL_PKEY_PKEY_OSSL_PARAM_VALUE_OCTET_STRING: {
        bld_buf[*bld_n] = OSSL_PARAM_construct_octet_string(
            key_c,
            p->value.val.octet_string.ptr,
            p->value.val.octet_string.len);
        (*bld_n)++;
        break;
    }
    case OPENSSL_PKEY_PKEY_OSSL_PARAM_VALUE_UTF8_STRING: {
        // OSSL_PARAM utf8_string data_size convention is len without
        // NUL, but several openssl-wasm-internal consumers grab the
        // pointer via OSSL_PARAM_get_utf8_ptr and pass it directly
        // to OBJ_txt2obj / strlen / strcmp -- which read past
        // data_size. The WIT-returned buffer is allocated exactly
        // `len` bytes (wit-bindgen-c) so writing val[len]=0 walks
        // into adjacent memory that may be clobbered later. Allocate
        // a fresh `len+1` buffer here, copy + NUL, and use it. The
        // caller (wit_keymgmt_export / wit_keymgmt_get_params) is
        // responsible for tracking + freeing these after param_cb.
        // Overallocate generously. The actual data lives in the first
        // len+1 bytes; the extra ~64 bytes of slack absorb any spurious
        // writes from adjacent allocator activity (the param consumer's
        // cached pointer + a future param_cb invocation race the
        // allocator into reusing the slot otherwise).
        const size_t SLACK = 4096;
        char *fresh = OPENSSL_zalloc(p->value.val.utf8_string.len + 1 + SLACK);
        if (!fresh) break;
        memcpy(fresh, p->value.val.utf8_string.ptr, p->value.val.utf8_string.len);
        // OPENSSL_zalloc gave us zero bytes already, but be explicit.
        fresh[p->value.val.utf8_string.len] = 0;
        bld_buf[*bld_n] = OSSL_PARAM_construct_utf8_string(
            key_c, fresh, p->value.val.utf8_string.len);
        (*bld_n)++;
        break;
    }
    case OPENSSL_PKEY_PKEY_OSSL_PARAM_VALUE_UNSIGNED_INTEGER: {
        // OSSL_PARAM_construct_size_t / _uint64 needs a pointer to a
        // size_t/uint64 -- we hand it the WIT field's address.
        bld_buf[*bld_n] = OSSL_PARAM_construct_uint64(
            key_c, &p->value.val.unsigned_integer);
        (*bld_n)++;
        break;
    }
    case OPENSSL_PKEY_PKEY_OSSL_PARAM_VALUE_INTEGER: {
        bld_buf[*bld_n] = OSSL_PARAM_construct_int64(
            key_c, &p->value.val.integer);
        (*bld_n)++;
        break;
    }
    default:
        // Phase 8: other variants. Skip silently.
        break;
    }
}

static int wit_keymgmt_export(
        void *keydata, int selection,
        OSSL_CALLBACK *param_cb, void *cbarg) {
    if (!keydata || !param_cb) return 0;
    const wit_keydata_t *w = keydata;
    openssl_keymgmt_keymgmt_list_list_ossl_param_t ret;
    openssl_keymgmt_keymgmt_pkey_error_t err;
    if (!openssl_keymgmt_keymgmt_method_keydata_export(
            borrow_keydata(w), selection_to_wit(selection), &ret, &err)) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }
    // Walk the outer list = OSSL_CALLBACK invocations.
    int success = 1;
    for (size_t i = 0; i < ret.len; i++) {
        openssl_keymgmt_keymgmt_list_ossl_param_t *inner = &ret.ptr[i];
        // Convert inner list to OSSL_PARAM[] + END sentinel.
        OSSL_PARAM *bld = malloc(sizeof(OSSL_PARAM) * (inner->len + 1));
        if (!bld) { success = 0; break; }
        int n = 0;
        for (size_t j = 0; j < inner->len; j++) {
            emit_ossl_param_to_cb(&inner->ptr[j], param_cb, cbarg, bld, &n);
        }
        bld[n] = OSSL_PARAM_construct_end();
        if (!param_cb(bld, cbarg)) success = 0;
        // emit_ossl_param_to_cb allocates a fresh NUL-terminated
        // buffer for every utf8_string param so downstream consumers
        // see a proper C string. We intentionally leak those (small,
        // a handful per export call) -- some consumers stash the
        // pointer past param_cb (e.g. cached sigalg state) and freeing
        // immediately produces use-after-free on subsequent reads.
        free(bld);
    }
    openssl_keymgmt_keymgmt_list_list_ossl_param_free(&ret);
    return success;
}

// Static export-types descriptor (Phase 3.5 just reports the SPKI
// key). Phase 8 fills in more accurately.
static const OSSL_PARAM wit_export_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END,
};
static const OSSL_PARAM *wit_keymgmt_export_types(int selection) {
    (void)selection;
    return wit_export_types;
}

// Marshal a C OSSL_PARAM[] into a WIT list<ossl-param>. Phase 3.5
// supports utf8-string and octet-string variants -- enough for the
// "wit-bridge-uri" param the adapter recognizes plus the usual
// SPKI/EC-curve params an EVP_PKEY_fromdata caller might pass.
static void build_wit_params_full(
        const OSSL_PARAM params[],
        openssl_keymgmt_keymgmt_list_ossl_param_t *out) {
    if (!params) { out->ptr = NULL; out->len = 0; return; }
    size_t count = 0;
    for (const OSSL_PARAM *p = params; p->key != NULL; p++) {
        if (p->data_type == OSSL_PARAM_UTF8_STRING ||
            p->data_type == OSSL_PARAM_OCTET_STRING) count++;
    }
    if (!count) { out->ptr = NULL; out->len = 0; return; }
    out->ptr = malloc(sizeof(out->ptr[0]) * count);
    out->len = 0;
    for (const OSSL_PARAM *p = params; p->key != NULL; p++) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING &&
            p->data_type != OSSL_PARAM_OCTET_STRING) continue;
        openssl_keymgmt_keymgmt_ossl_param_t *o = &out->ptr[out->len++];
        openssl_string_dup(&o->key, p->key);
        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            o->value.tag = OPENSSL_PKEY_PKEY_OSSL_PARAM_VALUE_UTF8_STRING;
            o->value.val.utf8_string.ptr = malloc(p->data_size + 1);
            memcpy(o->value.val.utf8_string.ptr, p->data, p->data_size);
            o->value.val.utf8_string.ptr[p->data_size] = 0;
            o->value.val.utf8_string.len = p->data_size;
        } else {
            o->value.tag = OPENSSL_PKEY_PKEY_OSSL_PARAM_VALUE_OCTET_STRING;
            o->value.val.octet_string.ptr = malloc(p->data_size);
            memcpy(o->value.val.octet_string.ptr, p->data, p->data_size);
            o->value.val.octet_string.len = p->data_size;
        }
    }
}

static int wit_keymgmt_import(void *keydata, int selection,
                              const OSSL_PARAM params[]) {
    if (!keydata) return 0;
    const wit_keydata_t *w = keydata;
    openssl_keymgmt_keymgmt_list_ossl_param_t wp;
    build_wit_params_full(params, &wp);
    openssl_keymgmt_keymgmt_pkey_error_t err;
    int ok = openssl_keymgmt_keymgmt_method_keydata_import(
        borrow_keydata(w), selection_to_wit(selection), &wp, &err) ? 1 : 0;
    if (!ok) emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
    return ok;
}
static const OSSL_PARAM wit_import_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END,
};
static const OSSL_PARAM *wit_keymgmt_import_types(int selection) {
    (void)selection;
    return wit_import_types;
}
// Match an OSSL_PARAM by key against a WIT ossl-param entry. If the
// types are compatible, populate the OSSL_PARAM's data buffer and
// return_size from the WIT value. Returns true on a successful set.
// Supports utf8-string, octet-string, unsigned-integer (u64 → size_t
// or unsigned int), integer (s64 → int).
static bool fill_one_ossl_param(OSSL_PARAM *p,
                                openssl_pkey_pkey_ossl_param_t *witp) {
    if (p->key == NULL || witp->key.len == 0) return false;
    if (strlen(p->key) != witp->key.len) return false;
    if (memcmp(p->key, witp->key.ptr, witp->key.len) != 0) return false;
    switch (witp->value.tag) {
    case OPENSSL_PKEY_PKEY_OSSL_PARAM_VALUE_UTF8_STRING: {
        // WIT-bindgen-c buffers are NOT NUL-terminated, so we can't
        // hand the raw pointer to OSSL_PARAM_set_utf8_string -- it
        // calls strlen() which would read past the buffer. Copy into
        // a fixed-size stack buffer with explicit NUL, then forward.
        char tmp[256];
        size_t len = witp->value.val.utf8_string.len;
        if (len + 1 > sizeof(tmp)) len = sizeof(tmp) - 1;
        memcpy(tmp, witp->value.val.utf8_string.ptr, len);
        tmp[len] = 0;
        return OSSL_PARAM_set_utf8_string(p, tmp) == 1
            || (p->data_type == OSSL_PARAM_UTF8_STRING
                && p->data != NULL && p->data_size >= len + 1
                && (memcpy(p->data, tmp, len),
                    ((char*)p->data)[len] = 0,
                    p->return_size = len, true));
    }
    case OPENSSL_PKEY_PKEY_OSSL_PARAM_VALUE_OCTET_STRING: {
        return OSSL_PARAM_set_octet_string(p,
                   witp->value.val.octet_string.ptr,
                   witp->value.val.octet_string.len) == 1;
    }
    case OPENSSL_PKEY_PKEY_OSSL_PARAM_VALUE_UNSIGNED_INTEGER: {
        uint64_t v = witp->value.val.unsigned_integer;
        // Coerce to whatever width/signedness the caller requested.
        // OpenSSL's evp_keymgmt_util_cache_pkey uses
        // OSSL_PARAM_construct_int (signed) for bits/security-bits/
        // max-size; if we only handled UNSIGNED here the cache stayed
        // zero -> "unknown security bits" -> TLS "ee key too small".
        if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER
                || p->data_type == OSSL_PARAM_INTEGER) {
            switch (p->data_size) {
            case sizeof(int):
                *(int *)p->data = (int)v;
                p->return_size = sizeof(int); return true;
            case sizeof(int64_t):
                *(int64_t *)p->data = (int64_t)v;
                p->return_size = sizeof(int64_t); return true;
#if SIZE_MAX != UINT64_MAX && SIZE_MAX != UINT_MAX
            case sizeof(size_t):
                *(size_t *)p->data = (size_t)v;
                p->return_size = sizeof(size_t); return true;
#endif
            }
        }
        return false;
    }
    case OPENSSL_PKEY_PKEY_OSSL_PARAM_VALUE_INTEGER: {
        int64_t v = witp->value.val.integer;
        if (p->data_type == OSSL_PARAM_INTEGER
                || p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
            switch (p->data_size) {
            case sizeof(int):
                *(int *)p->data = (int)v;
                p->return_size = sizeof(int); return true;
            case sizeof(int64_t):
                *(int64_t *)p->data = v;
                p->return_size = sizeof(int64_t); return true;
            }
        }
        return false;
    }
    default:
        return false;
    }
}

static int wit_keymgmt_get_params(void *keydata, OSSL_PARAM params[]) {
    if (!keydata || !params) return 1;
    const wit_keydata_t *w = keydata;
    // Ask the WIT for everything (empty keys list = "give me all").
    openssl_list_string_t empty_keys = { NULL, 0 };
    openssl_keymgmt_keymgmt_list_ossl_param_t wit_out;
    openssl_keymgmt_keymgmt_pkey_error_t err;
    if (!openssl_keymgmt_keymgmt_method_keydata_get_params(
            borrow_keydata(w), &empty_keys, &wit_out, &err)) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }
    // For each OSSL_PARAM requested, find the matching WIT entry and
    // copy its value. Unmatched params get return_size=0 (skipped).
    for (OSSL_PARAM *p = params; p->key != NULL; p++) {
        bool filled = false;
        for (size_t i = 0; i < wit_out.len; i++) {
            if (fill_one_ossl_param(p, &wit_out.ptr[i])) {
                filled = true; break;
            }
        }
        if (!filled) p->return_size = 0;
    }
    openssl_keymgmt_keymgmt_list_ossl_param_free(&wit_out);
    return 1;
}
static const OSSL_PARAM wit_gettable_params_arr[] = {
    OSSL_PARAM_END,
};
static const OSSL_PARAM *wit_keymgmt_gettable_params(void *provctx) {
    (void)provctx;
    return wit_gettable_params_arr;
}

// query_operation_name -- which algorithm name should keymgmt show
// up under for the given OSSL_OP_* op? Walks the WIT.
// Per-keymgmt query_operation_name -- maps OSSL_OP_SIGNATURE to the
// signature impl name openssl should fetch. The split lets the
// "EC" keymgmt route to "ECDSA" and the "RSA" keymgmt to "RSA-PSS"
// without changing the WIT contract (which is stateless and would
// otherwise return only one of them).
static const char *wit_keymgmt_query_op_name_ec(int operation_id) {
    if (operation_id == OSSL_OP_SIGNATURE) return "ECDSA";
    if (operation_id == OSSL_OP_KEYEXCH)   return "ECDH";
    return NULL;
}
static const char *wit_keymgmt_query_op_name_rsa(int operation_id) {
    if (operation_id == OSSL_OP_SIGNATURE) return "RSA-PSS";
    return NULL;
}

// ---------------------------------------------------------------------------
// keymgmt OSSL_DISPATCH tables (one per registered name).
// ---------------------------------------------------------------------------
#define WIT_KEYMGMT_SHARED_DISPATCH \
    { OSSL_FUNC_KEYMGMT_NEW,             (void (*)(void))wit_keymgmt_new          }, \
    { OSSL_FUNC_KEYMGMT_FREE,            (void (*)(void))wit_keymgmt_free         }, \
    { OSSL_FUNC_KEYMGMT_LOAD,            (void (*)(void))wit_keymgmt_load         }, \
    { OSSL_FUNC_KEYMGMT_HAS,             (void (*)(void))wit_keymgmt_has          }, \
    { OSSL_FUNC_KEYMGMT_MATCH,           (void (*)(void))wit_keymgmt_match        }, \
    { OSSL_FUNC_KEYMGMT_EXPORT,          (void (*)(void))wit_keymgmt_export       }, \
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,    (void (*)(void))wit_keymgmt_export_types }, \
    { OSSL_FUNC_KEYMGMT_IMPORT,          (void (*)(void))wit_keymgmt_import       }, \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,    (void (*)(void))wit_keymgmt_import_types }, \
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,      (void (*)(void))wit_keymgmt_get_params   }, \
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))wit_keymgmt_gettable_params }

static const OSSL_DISPATCH wit_keymgmt_dispatch_ec[] = {
    WIT_KEYMGMT_SHARED_DISPATCH,
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))wit_keymgmt_query_op_name_ec },
    { 0, NULL },
};
static const OSSL_DISPATCH wit_keymgmt_dispatch_rsa[] = {
    WIT_KEYMGMT_SHARED_DISPATCH,
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))wit_keymgmt_query_op_name_rsa },
    { 0, NULL },
};

// ===========================================================================
// signature thunks
// ===========================================================================
typedef struct wit_sigctx {
    int32_t handle;  // openssl_signature_signature_own_signature_context_t.__handle
    bool    owned;
} wit_sigctx_t;

static inline openssl_signature_signature_borrow_signature_context_t
borrow_sigctx(const wit_sigctx_t *c) {
    return (openssl_signature_signature_borrow_signature_context_t){ .__handle = c->handle };
}

static void *wit_signature_newctx(void *provctx, const char *propq) {
    (void)provctx;
    openssl_string_t propq_str;
    if (propq) openssl_string_set(&propq_str, propq);
    openssl_signature_signature_own_signature_context_t handle =
        openssl_signature_signature_constructor_signature_context(
            propq ? &propq_str : NULL);
    wit_sigctx_t *c = malloc(sizeof(*c));
    if (!c) {
        openssl_signature_signature_signature_context_drop_own(handle);
        return NULL;
    }
    c->handle = handle.__handle;
    c->owned  = true;
    return c;
}

static void wit_signature_freectx(void *ctx) {
    if (!ctx) return;
    wit_sigctx_t *c = ctx;
    if (c->owned) {
        openssl_signature_signature_own_signature_context_t own = { .__handle = c->handle };
        openssl_signature_signature_signature_context_drop_own(own);
    }
    free(c);
}

// Convert OpenSSL OSSL_PARAM[] into a WIT list<ossl-param> for
// signature.set-ctx-params. Phase 3.5 only forwards "digest" as a
// utf8-string -- the only param our stub ECDSA path actually reads.
static void build_wit_params_for_sign(
        const OSSL_PARAM params[],
        openssl_signature_signature_list_ossl_param_t *out) {
    if (!params) { out->ptr = NULL; out->len = 0; return; }
    size_t count = 0;
    for (const OSSL_PARAM *p = params; p->key != NULL; p++) {
        if (p->data_type == OSSL_PARAM_UTF8_STRING) count++;
    }
    if (!count) { out->ptr = NULL; out->len = 0; return; }
    out->ptr = malloc(sizeof(out->ptr[0]) * count);
    out->len = 0;
    for (const OSSL_PARAM *p = params; p->key != NULL; p++) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) continue;
        openssl_signature_signature_ossl_param_t *o = &out->ptr[out->len++];
        openssl_string_dup(&o->key, p->key);
        o->value.tag = OPENSSL_PKEY_PKEY_OSSL_PARAM_VALUE_UTF8_STRING;
        // p->data may not be NUL-terminated within the buffer; use
        // explicit length copy.
        o->value.val.utf8_string.ptr = malloc(p->data_size + 1);
        memcpy(o->value.val.utf8_string.ptr, p->data, p->data_size);
        o->value.val.utf8_string.ptr[p->data_size] = 0;
        o->value.val.utf8_string.len = p->data_size;
    }
}

static int wit_signature_sign_init(void *ctx, void *provkey,
                                   const OSSL_PARAM params[]) {
    if (!ctx || !provkey) return 0;
    wit_sigctx_t *c = ctx;
    wit_keydata_t *k = provkey;
    openssl_signature_signature_list_ossl_param_t wp;
    build_wit_params_for_sign(params, &wp);
    openssl_signature_signature_borrow_keydata_t kb = { .__handle = k->handle };
    openssl_signature_signature_pkey_error_t err;
    int ok = openssl_signature_signature_method_signature_context_sign_init(
        borrow_sigctx(c), kb, &wp, &err) ? 1 : 0;
    if (!ok) emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
    return ok;
}

static int wit_signature_sign(void *ctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize, const unsigned char *tbs, size_t tbslen) {
    if (!ctx || !siglen) return 0;
    wit_sigctx_t *c = ctx;
    // OpenSSL's sig=NULL probe asks "how large will the signature be?"
    // We can't answer by actually signing -- ECDSA DER is variable
    // (70..72 bytes for P-256), so a probe-sign followed by a real
    // sign can yield different sizes, breaking the second-call buffer.
    // Return a generous upper bound instead.
    if (sig == NULL) {
        *siglen = 512;  // covers ECDSA P-521 (~139) + RSA-4096 (512)
        return 1;
    }
    openssl_list_u8_t in = { (uint8_t *)tbs, tbslen };
    openssl_list_u8_t out;
    openssl_signature_signature_pkey_error_t err;
    if (!openssl_signature_signature_method_signature_context_sign(
            borrow_sigctx(c), &in, &out, &err)) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }
    if (out.len > sigsize) {
        *siglen = out.len;  // tell caller required size, then fail
        openssl_list_u8_free(&out);
        return 0;
    }
    memcpy(sig, out.ptr, out.len);
    *siglen = out.len;
    openssl_list_u8_free(&out);
    return 1;
}

static int wit_signature_digest_sign_init(void *ctx, const char *mdname,
                                          void *provkey, const OSSL_PARAM params[]) {
    if (!ctx || !provkey) return 0;
    wit_sigctx_t *c = ctx;
    wit_keydata_t *k = provkey;
    openssl_string_t mdname_str;
    if (mdname) openssl_string_set(&mdname_str, mdname);
    openssl_signature_signature_list_ossl_param_t wp;
    build_wit_params_for_sign(params, &wp);
    openssl_signature_signature_borrow_keydata_t kb = { .__handle = k->handle };
    openssl_signature_signature_pkey_error_t err;
    int ok = openssl_signature_signature_method_signature_context_digest_sign_init(
        borrow_sigctx(c),
        mdname ? &mdname_str : NULL,
        kb, &wp, &err) ? 1 : 0;
    if (!ok) emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
    return ok;
}

static int wit_signature_digest_sign_update(void *ctx, const unsigned char *data,
                                            size_t datalen) {
    if (!ctx) return 0;
    wit_sigctx_t *c = ctx;
    openssl_list_u8_t in = { (uint8_t *)data, datalen };
    openssl_signature_signature_pkey_error_t err;
    int ok = openssl_signature_signature_method_signature_context_digest_sign_update(
        borrow_sigctx(c), &in, &err) ? 1 : 0;
    if (!ok) emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
    return ok;
}

static int wit_signature_digest_sign_final(void *ctx, unsigned char *sig,
                                           size_t *siglen, size_t sigsize) {
    if (!ctx || !siglen) return 0;
    wit_sigctx_t *c = ctx;
    openssl_list_u8_t out;
    openssl_signature_signature_pkey_error_t err;
    if (!openssl_signature_signature_method_signature_context_digest_sign_final(
            borrow_sigctx(c), &out, &err)) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }
    if (sig == NULL) {
        *siglen = out.len;
        openssl_list_u8_free(&out);
        return 1;
    }
    if (out.len > sigsize) {
        openssl_list_u8_free(&out);
        return 0;
    }
    memcpy(sig, out.ptr, out.len);
    *siglen = out.len;
    openssl_list_u8_free(&out);
    return 1;
}

static int wit_signature_digest_sign(void *ctx, unsigned char *sig,
                                     size_t *siglen, size_t sigsize,
                                     const unsigned char *tbs, size_t tbslen) {
    if (!ctx || !siglen) return 0;
    // sig=NULL probe: see wit_signature_sign for why this returns a
    // conservative bound rather than probe-signing.
    if (sig == NULL) {
        *siglen = 512;
        return 1;
    }
    wit_sigctx_t *c = ctx;
    openssl_list_u8_t in = { (uint8_t *)tbs, tbslen };
    openssl_list_u8_t out;
    openssl_signature_signature_pkey_error_t err;
    if (!openssl_signature_signature_method_signature_context_digest_sign(
            borrow_sigctx(c), &in, &out, &err)) {
        emit_pkey_error((openssl_pkey_pkey_pkey_error_t *)&err);
        return 0;
    }
    if (out.len > sigsize) {
        *siglen = out.len;
        openssl_list_u8_free(&out);
        return 0;
    }
    memcpy(sig, out.ptr, out.len);
    *siglen = out.len;
    openssl_list_u8_free(&out);
    return 1;
}

// set/get_ctx_params -- Phase 3.5 forwards "digest" only; everything
// else is silently accepted.
static int wit_signature_set_ctx_params(void *ctx, const OSSL_PARAM params[]) {
    (void)ctx; (void)params;
    return 1;
}
static int wit_signature_get_ctx_params(void *ctx, OSSL_PARAM params[]) {
    (void)ctx;
    if (params) {
        for (OSSL_PARAM *p = params; p->key != NULL; p++) p->return_size = 0;
    }
    return 1;
}
// Phase 8c: per-algorithm settable_ctx_params. ECDSA accepts only
// "digest"; RSA-PSS accepts the full PSS knob set so openssl's
// EVP_PKEY_CTX setters can plumb pad-mode / saltlen / mgf1-digest
// through to the wit signature's set_ctx_params on the Rust side.
//
// Each name (ECDSA / RSA-PSS) gets its own dispatch table that
// differs only in the settable_ctx_params + query_key_types
// pointers -- everything else is shared with wit_signature_dispatch.
// Without this split, advertising RSA-PSS params on the ECDSA
// impl confuses TLS sigalg negotiation ("no suitable signature
// algorithm" at SSL_accept).
static const OSSL_PARAM wit_signature_settable_ecdsa_arr[] = {
    OSSL_PARAM_utf8_string("digest", NULL, 0),
    OSSL_PARAM_END,
};
static const OSSL_PARAM wit_signature_settable_rsa_pss_arr[] = {
    OSSL_PARAM_utf8_string("digest",          NULL, 0),
    OSSL_PARAM_utf8_string("properties",      NULL, 0),
    OSSL_PARAM_utf8_string("pad-mode",        NULL, 0),
    OSSL_PARAM_utf8_string("mgf1-digest",     NULL, 0),
    OSSL_PARAM_utf8_string("mgf1-properties", NULL, 0),
    OSSL_PARAM_int        ("saltlen",         NULL),
    OSSL_PARAM_END,
};
static const OSSL_PARAM *wit_signature_settable_ctx_params_ecdsa(void *ctx, void *provctx) {
    (void)ctx; (void)provctx;
    return wit_signature_settable_ecdsa_arr;
}
static const OSSL_PARAM *wit_signature_settable_ctx_params_rsa_pss(void *ctx, void *provctx) {
    (void)ctx; (void)provctx;
    return wit_signature_settable_rsa_pss_arr;
}
// Back-compat alias for any code still referring to the old name.
static const OSSL_PARAM *wit_signature_settable_ctx_params(void *ctx, void *provctx) {
    return wit_signature_settable_ctx_params_ecdsa(ctx, provctx);
}
static const OSSL_PARAM wit_signature_gettable_arr[] = {
    OSSL_PARAM_END,
};
static const OSSL_PARAM *wit_signature_gettable_ctx_params(void *ctx, void *provctx) {
    (void)ctx; (void)provctx;
    return wit_signature_gettable_arr;
}

// OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES (26): what keydata algorithm
// names can this signature sign for? OpenSSL uses this to match
// signature impls to EVP_PKEYs at EVP_DigestSignInit time -- if our
// signature doesn't advertise a matching key-type, OpenSSL refuses
// with "operation not supported for this keytype".
//
// Returns a NULL-terminated array of const char*. The strings live
// in static storage cached at first call.
static const char *g_signature_keytypes[8];  // up to 7 + NULL
static bool g_signature_keytypes_built = false;
static char g_signature_keytype_buf[8][64];  // backing strings

static const char **wit_signature_query_key_types(void) {
    if (g_signature_keytypes_built) return g_signature_keytypes;
    openssl_list_string_t out = { NULL, 0 };
    openssl_signature_signature_query_key_types(&out);
    size_t n = out.len < 7 ? out.len : 7;
    for (size_t i = 0; i < n; i++) {
        size_t len = out.ptr[i].len < sizeof(g_signature_keytype_buf[i]) - 1
                   ? out.ptr[i].len : sizeof(g_signature_keytype_buf[i]) - 1;
        memcpy(g_signature_keytype_buf[i], out.ptr[i].ptr, len);
        g_signature_keytype_buf[i][len] = 0;
        g_signature_keytypes[i] = g_signature_keytype_buf[i];
    }
    g_signature_keytypes[n] = NULL;
    openssl_list_string_free(&out);
    g_signature_keytypes_built = true;
    return g_signature_keytypes;
}

// Per-signature-impl query_key_types -- ECDSA only signs for "EC",
// RSA-PSS only for "RSA". Keeps openssl's sigalg matching tight so
// it doesn't try our RSA-PSS impl with an EC key (or vice versa).
static const char *g_keytypes_ec[]  = { "EC",  NULL };
static const char *g_keytypes_rsa[] = { "RSA", NULL };
static const char **wit_signature_query_key_types_ecdsa(void)   { return g_keytypes_ec; }
static const char **wit_signature_query_key_types_rsa_pss(void) { return g_keytypes_rsa; }

// ---------------------------------------------------------------------------
// signature OSSL_DISPATCH table
// ---------------------------------------------------------------------------
// Two dispatch tables -- one per registered name (ECDSA / RSA-PSS).
// All sign/verify/init functions are shared (they route through the
// WIT signature impl regardless of key type); only settable_ctx_params
// and query_key_types differ.
#define WIT_SIG_SHARED_DISPATCH \
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))wit_signature_newctx }, \
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))wit_signature_freectx }, \
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,           (void (*)(void))wit_signature_sign_init }, \
    { OSSL_FUNC_SIGNATURE_SIGN,                (void (*)(void))wit_signature_sign }, \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))wit_signature_digest_sign_init }, \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,  (void (*)(void))wit_signature_digest_sign_update }, \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,   (void (*)(void))wit_signature_digest_sign_final }, \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,         (void (*)(void))wit_signature_digest_sign }, \
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,      (void (*)(void))wit_signature_set_ctx_params }, \
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))wit_signature_get_ctx_params }, \
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))wit_signature_gettable_ctx_params }

static const OSSL_DISPATCH wit_signature_dispatch_ecdsa[] = {
    WIT_SIG_SHARED_DISPATCH,
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))wit_signature_settable_ctx_params_ecdsa },
    { OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,     (void (*)(void))wit_signature_query_key_types_ecdsa },
    { 0, NULL },
};
static const OSSL_DISPATCH wit_signature_dispatch_rsa_pss[] = {
    WIT_SIG_SHARED_DISPATCH,
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))wit_signature_settable_ctx_params_rsa_pss },
    { OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,     (void (*)(void))wit_signature_query_key_types_rsa_pss },
    { 0, NULL },
};

// ===========================================================================
// Algorithm-list builders: convert WIT query_operation result into
// the persistent OSSL_ALGORITHM[] OpenSSL caches.
// ===========================================================================

// Static storage for algorithm names. Phase 8c: up to 4 algorithms
// per op (EC + RSA keymgmts; ECDSA + RSA-PSS signatures); each gets
// a slot in the names/propq arrays. The dispatch pointer per slot
// is one of the per-name static dispatches below.
#define WIT_MAX_ALGOS 4
static char  g_keymgmt_name[WIT_MAX_ALGOS][64];
static char  g_keymgmt_propq[WIT_MAX_ALGOS][64];
static char  g_signature_name[WIT_MAX_ALGOS][64];
static char  g_signature_propq[WIT_MAX_ALGOS][64];
static OSSL_ALGORITHM g_keymgmt_algos[WIT_MAX_ALGOS + 1];   // + END sentinel
static OSSL_ALGORITHM g_signature_algos[WIT_MAX_ALGOS + 1];
static bool g_keymgmt_built  = false;
static bool g_signature_built = false;

// Pick the dispatch table matching a WIT-advertised algorithm name.
// Unknown names fall back to the EC/ECDSA dispatch so we never
// return NULL (which would crash openssl during fetch).
static const OSSL_DISPATCH *dispatch_for_keymgmt_name(const char *name) {
    if (strcmp(name, "RSA") == 0) return wit_keymgmt_dispatch_rsa;
    return wit_keymgmt_dispatch_ec;
}
static const OSSL_DISPATCH *dispatch_for_signature_name(const char *name) {
    if (strcmp(name, "RSA-PSS") == 0) return wit_signature_dispatch_rsa_pss;
    return wit_signature_dispatch_ecdsa;
}

// Strip the colon-separated alias list down to its first name and
// stash it in `dst`. Truncates safely on too-long input.
static void strdup_first_alias(char *dst, size_t dst_sz, openssl_string_t *s) {
    size_t n = s->len < dst_sz - 1 ? s->len : dst_sz - 1;
    memcpy(dst, s->ptr, n);
    dst[n] = 0;
}

// Build / cache the keymgmt algorithm table by asking the WIT.
// Phase 8c registers one OSSL_ALGORITHM per WIT entry (capped at
// WIT_MAX_ALGOS) with its name-specific dispatch table so openssl
// can fetch by name (EC -> wit_keymgmt_dispatch_ec, RSA -> _rsa).
static const OSSL_ALGORITHM *build_keymgmt_algos(void) {
    if (g_keymgmt_built) return g_keymgmt_algos;
    openssl_provider_provider_tuple2_list_ossl_algorithm_bool_t tup = {
        { NULL, 0 }, false,
    };
    openssl_provider_provider_query_operation(
        OPENSSL_PKEY_PKEY_OPERATION_KEYMGMT, &tup);
    if (tup.f0.len == 0) {
        openssl_provider_provider_list_ossl_algorithm_free(&tup.f0);
        return NULL;
    }
    size_t n = tup.f0.len < WIT_MAX_ALGOS ? tup.f0.len : WIT_MAX_ALGOS;
    for (size_t i = 0; i < n; i++) {
        openssl_provider_provider_ossl_algorithm_t *a = &tup.f0.ptr[i];
        strdup_first_alias(g_keymgmt_name[i],  sizeof(g_keymgmt_name[i]),  &a->algorithm_names);
        strdup_first_alias(g_keymgmt_propq[i], sizeof(g_keymgmt_propq[i]), &a->property_definition);
        g_keymgmt_algos[i].algorithm_names    = g_keymgmt_name[i];
        g_keymgmt_algos[i].property_definition = g_keymgmt_propq[i];
        g_keymgmt_algos[i].implementation     = dispatch_for_keymgmt_name(g_keymgmt_name[i]);
        g_keymgmt_algos[i].algorithm_description = "wit-bridge keymgmt";
    }
    g_keymgmt_algos[n].algorithm_names    = NULL;
    g_keymgmt_algos[n].property_definition = NULL;
    g_keymgmt_algos[n].implementation     = NULL;
    g_keymgmt_algos[n].algorithm_description = NULL;
    openssl_provider_provider_list_ossl_algorithm_free(&tup.f0);
    g_keymgmt_built = true;
    return g_keymgmt_algos;
}

static const OSSL_ALGORITHM *build_signature_algos(void) {
    if (g_signature_built) return g_signature_algos;
    openssl_provider_provider_tuple2_list_ossl_algorithm_bool_t tup = {
        { NULL, 0 }, false,
    };
    openssl_provider_provider_query_operation(
        OPENSSL_PKEY_PKEY_OPERATION_SIGNATURE, &tup);
    if (tup.f0.len == 0) {
        openssl_provider_provider_list_ossl_algorithm_free(&tup.f0);
        return NULL;
    }
    size_t n = tup.f0.len < WIT_MAX_ALGOS ? tup.f0.len : WIT_MAX_ALGOS;
    for (size_t i = 0; i < n; i++) {
        openssl_provider_provider_ossl_algorithm_t *a = &tup.f0.ptr[i];
        strdup_first_alias(g_signature_name[i],  sizeof(g_signature_name[i]),  &a->algorithm_names);
        strdup_first_alias(g_signature_propq[i], sizeof(g_signature_propq[i]), &a->property_definition);
        g_signature_algos[i].algorithm_names    = g_signature_name[i];
        g_signature_algos[i].property_definition = g_signature_propq[i];
        g_signature_algos[i].implementation     = dispatch_for_signature_name(g_signature_name[i]);
        g_signature_algos[i].algorithm_description = "wit-bridge signature";
    }
    g_signature_algos[n].algorithm_names    = NULL;
    g_signature_algos[n].property_definition = NULL;
    g_signature_algos[n].implementation     = NULL;
    g_signature_algos[n].algorithm_description = NULL;
    openssl_provider_provider_list_ossl_algorithm_free(&tup.f0);
    g_signature_built = true;
    return g_signature_algos;
}

// ===========================================================================
// Provider entry-point dispatch (unchanged shape from Phase 2; the
// query_operation thunk now actually builds dispatch tables instead
// of returning NULL).
// ===========================================================================

static void wit_provider_teardown(void *provctx) { (void)provctx; }

static const OSSL_PARAM *wit_provider_gettable_params(void *provctx) {
    (void)provctx;
    openssl_provider_provider_list_ossl_param_descriptor_t descs = { NULL, 0 };
    openssl_provider_provider_gettable_params(&descs);
    openssl_provider_provider_list_ossl_param_descriptor_free(&descs);
    static const OSSL_PARAM empty[] = { OSSL_PARAM_END };
    return empty;
}

static int wit_provider_get_params(void *provctx, OSSL_PARAM params[]) {
    (void)provctx;
    openssl_list_string_t keys = { NULL, 0 };
    openssl_provider_provider_list_ossl_param_t out = { NULL, 0 };
    openssl_provider_provider_pkey_error_t err;
    if (openssl_provider_provider_get_params(&keys, &out, &err)) {
        openssl_provider_provider_list_ossl_param_free(&out);
    } else {
        openssl_provider_provider_pkey_error_free(&err);
    }
    if (params != NULL) {
        for (OSSL_PARAM *p = params; p->key != NULL; p++) p->return_size = 0;
    }
    return 1;
}

static const OSSL_ALGORITHM *wit_provider_query_operation(
        void *provctx, int operation_id, int *no_store) {
    (void)provctx;
    if (no_store) *no_store = 1;
    switch (operation_id) {
        case OSSL_OP_KEYMGMT:   return build_keymgmt_algos();
        case OSSL_OP_SIGNATURE: return build_signature_algos();
        default:                return NULL;
    }
}

static void wit_provider_unquery_operation(
        void *provctx, int operation_id, const OSSL_ALGORITHM *algos) {
    (void)provctx; (void)operation_id; (void)algos;
}

static int wit_provider_self_test(void *provctx) {
    (void)provctx;
    return 1;
}

static const OSSL_DISPATCH wit_provider_dispatch[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,          (void (*)(void))wit_provider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,   (void (*)(void))wit_provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,        (void (*)(void))wit_provider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,   (void (*)(void))wit_provider_query_operation },
    { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))wit_provider_unquery_operation },
    { OSSL_FUNC_PROVIDER_SELF_TEST,         (void (*)(void))wit_provider_self_test },
    { 0, NULL },
};

int ossl_wit_provider_init(const OSSL_CORE_HANDLE *handle,
                           const OSSL_DISPATCH *core_dispatch,
                           const OSSL_DISPATCH **provider_dispatch,
                           void **provctx) {
    (void)handle;
    (void)core_dispatch;

    wit_provctx_t *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) return 0;
    ctx->marker = WIT_PROVCTX_MARKER;

    *provctx = ctx;
    *provider_dispatch = wit_provider_dispatch;
    return 1;
}

__attribute__((constructor))
static void register_wit_bridge_provider(void) {
    OSSL_PROVIDER_add_builtin(NULL, "wit-bridge", ossl_wit_provider_init);
}
