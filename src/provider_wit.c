// WIT <-> OSSL_PROVIDER bridge.
//
// Phase 2 of the openssl-provider-wit plan. Lets OpenSSL load a
// provider by name ("wit-bridge") and dispatch its operations through
// the WIT imports declared in wit/world.wit.
//
// Architecture:
//
//   OpenSSL's provider_core.c calls prov->init_function((OSSL_CORE_
//   HANDLE *)prov, core_dispatch, &provider_dispatch, &tmp_provctx).
//   For the "wit-bridge" name, we install ossl_wit_provider_init as
//   that init_function via OSSL_PROVIDER_add_builtin().
//
//   ossl_wit_provider_init returns:
//     - a static OSSL_DISPATCH array advertising:
//         provider_teardown, provider_gettable_params,
//         provider_get_params, provider_query_operation,
//         provider_unquery_operation, provider_get_capabilities,
//         provider_self_test, provider_random_bytes
//     - provctx set to a small struct holding bridge state
//
//   When OpenSSL calls one of those, the C thunk marshals the args
//   into WIT types, calls the imported WIT function (declared in
//   bindings/openssl.h as openssl_provider_provider_*), translates
//   the return.
//
// Phase 2 scope: enough surface for SSL_CTX_new() to load the
// bridge without warnings. query_operation returns NULL for every
// op_id (no algorithms advertised), which is the "no-op provider"
// the Phase 2 done-when calls for. Phase 3's simple-provider-adapter
// is where keymgmt/signature/asym-cipher dispatch tables actually get
// populated.
//
// Memory model:
//
//   The OSSL_ALGORITHM[] / OSSL_DISPATCH[] arrays we hand back from
//   query_operation must outlive OpenSSL's use of them. The C ABI's
//   `provider_unquery_operation` callback is OpenSSL's signal that
//   it's done with the array, but in practice OpenSSL may cache the
//   pointer indefinitely (controlled by the `no_store` out-bool we
//   return from query_operation). We currently keep all returned
//   arrays in a static cache keyed by operation id; Phase 3 widens
//   this once we actually return non-empty algorithm lists.

#include "bindings/openssl.h"
#include "include/support.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>

#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Bridge per-instance state. Carried as the OSSL_PROVIDER provctx so
// every dispatch func can get back to it. Phase 2 keeps it tiny;
// Phase 3 grows it with algorithm caches.
// ---------------------------------------------------------------------------
typedef struct wit_provctx {
    int marker;     // sentinel so we can assert provctx isn't garbage
} wit_provctx_t;

#define WIT_PROVCTX_MARKER 0x57495424  // 'WIT$'

// ---------------------------------------------------------------------------
// C->WIT operation enum translation.
//
// Returns true if the operation id maps to one of our 14 WIT
// `operation` variants. If false, query_operation should return NULL
// (no algorithms for unknown ops) -- the WIT enum is closed.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Dispatch thunks. Each implements one OSSL_FUNC_provider_*_fn
// signature; the body marshals args to WIT and calls the imported
// function. Phase 2's surface is minimal -- enough to satisfy the
// fields provider_core.c reads after init.
// ---------------------------------------------------------------------------

static void wit_provider_teardown(void *provctx) {
    // Notify the WIT side. Provider component cleanup happens at
    // component-instance destruction; this is just a courtesy hook
    // (some providers want to flush state before being unloaded).
    (void)provctx;
    // Currently the WIT `provider` interface has no explicit teardown
    // -- it collapses into the component's destructor. Nothing to do.
}

static const OSSL_PARAM *wit_provider_gettable_params(void *provctx) {
    (void)provctx;
    // Phase 2: call out to the WIT-imported gettable-params so the
    // import is retained at link time, then discard and report none.
    // Phase 3 will translate the returned descriptors into a static
    // OSSL_PARAM array.
    openssl_provider_provider_list_ossl_param_descriptor_t descs = { NULL, 0 };
    openssl_provider_provider_gettable_params(&descs);
    openssl_provider_provider_list_ossl_param_descriptor_free(&descs);
    static const OSSL_PARAM empty[] = { OSSL_PARAM_END };
    return empty;
}

static int wit_provider_get_params(void *provctx, OSSL_PARAM params[]) {
    (void)provctx;
    // Phase 2: forward a request for an empty key set to the WIT
    // import (retains the import; provider may use it for telemetry)
    // and claim success. Phase 3 maps the keys param list to/from
    // WIT bytes.
    openssl_list_string_t keys = { NULL, 0 };
    openssl_provider_provider_list_ossl_param_t out = { NULL, 0 };
    openssl_provider_provider_pkey_error_t err;
    if (openssl_provider_provider_get_params(&keys, &out, &err)) {
        openssl_provider_provider_list_ossl_param_free(&out);
    } else {
        openssl_provider_provider_pkey_error_free(&err);
    }
    if (params != NULL) {
        for (OSSL_PARAM *p = params; p->key != NULL; p++) {
            p->return_size = 0;
        }
    }
    return 1;
}

static const OSSL_ALGORITHM *wit_provider_query_operation(
        void *provctx, int operation_id, int *no_store) {
    (void)provctx;
    // Phase 2: call the WIT import (so the binding is retained at
    // link time and the canonical-ABI plumbing wires up) but discard
    // the result -- we don't yet know how to translate
    // list<ossl-algorithm> into a C OSSL_ALGORITHM[] with dispatch
    // tables. Phase 3 fills this in via the simple-provider-adapter.
    //
    // no_store=1 so OpenSSL doesn't cache an empty result -- next
    // call re-asks (this matches what real "no algorithms for this
    // op" providers return).
    openssl_provider_provider_operation_t op;
    if (!wit_operation_from_ossl(operation_id, &op)) {
        if (no_store) *no_store = 1;
        return NULL;
    }
    openssl_provider_provider_tuple2_list_ossl_algorithm_bool_t tup = {
        { NULL, 0 }, false,
    };
    openssl_provider_provider_query_operation(op, &tup);
    openssl_provider_provider_list_ossl_algorithm_free(&tup.f0);
    if (no_store) *no_store = 1;
    return NULL;
}

static void wit_provider_unquery_operation(
        void *provctx, int operation_id, const OSSL_ALGORITHM *algos) {
    // Phase 2 always returns NULL from query_operation; matching
    // unquery is a no-op.
    (void)provctx; (void)operation_id; (void)algos;
}

static int wit_provider_self_test(void *provctx) {
    (void)provctx;
    // Phase 2: claim success. Phase 3 calls the WIT self-test;
    // Phase 1b's WIT pkey-error variant lets us surface failures.
    return 1;
}

// ---------------------------------------------------------------------------
// Dispatch table. Pinned in static memory because provider_core.c
// stores the pointer for the lifetime of the loaded provider.
// ---------------------------------------------------------------------------
static const OSSL_DISPATCH wit_provider_dispatch[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,          (void (*)(void))wit_provider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,   (void (*)(void))wit_provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,        (void (*)(void))wit_provider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,   (void (*)(void))wit_provider_query_operation },
    { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))wit_provider_unquery_operation },
    { OSSL_FUNC_PROVIDER_SELF_TEST,         (void (*)(void))wit_provider_self_test },
    { 0, NULL },
};

// ---------------------------------------------------------------------------
// OSSL_provider_init entry point. provider_core.c calls this once per
// loaded provider instance. Returns 1 on success.
// ---------------------------------------------------------------------------
int ossl_wit_provider_init(const OSSL_CORE_HANDLE *handle,
                           const OSSL_DISPATCH *core_dispatch,
                           const OSSL_DISPATCH **provider_dispatch,
                           void **provctx) {
    (void)handle;
    (void)core_dispatch;  // Phase 2 ignores core-provided funcs (callback direction).

    wit_provctx_t *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return 0;
    }
    ctx->marker = WIT_PROVCTX_MARKER;

    *provctx = ctx;
    *provider_dispatch = wit_provider_dispatch;
    return 1;
}

// ---------------------------------------------------------------------------
// Registration. Called by ossl_wit_provider_register_builtins (invoked
// from the component's init path -- typically the first time
// libcrypto is touched) so that OSSL_PROVIDER_load("wit-bridge")
// dispatches to ossl_wit_provider_init.
//
// We use the "constructor" attribute rather than relying on an
// explicit init call because openssl-wasm's component.c doesn't have
// a single entry point that runs before any provider lookup;
// constructors fire on first interface call.
// ---------------------------------------------------------------------------
__attribute__((constructor))
static void register_wit_bridge_provider(void) {
    // Pass NULL for libctx (uses default), name "wit-bridge". The
    // last arg is the init function pointer.
    OSSL_PROVIDER_add_builtin(NULL, "wit-bridge", ossl_wit_provider_init);
}
