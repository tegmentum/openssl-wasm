noop-provider
=============

Trivial implementation of `openssl:provider-abi`. Every function
returns either "empty success" (the eight provider-level funcs
openssl-wasm's `src/provider_wit.c` shim actually calls during
`SSL_CTX_new`) or `pkey-error::not-supported` (the keymgmt /
signature / asym-cipher methods that are never invoked because
`query_operation` always returns no algorithms).

Used to verify the openssl-wasm side of the WIT-bridge works end-to-
end:

  bash examples/noop-provider/build.sh
  wac plug build/openssl-component.wasm \
    --plug examples/noop-provider/build/noop-provider.wasm \
    -o build/openssl-composed.wasm
  cd examples/host && \
    OPENSSL_WASM_COMPONENT=$PWD/../../build/openssl-composed.wasm \
    cargo test --release

All 105+ openssl-wasm functional tests pass against the composed
component -- the bridge is functionally transparent because the
built-in default OpenSSL provider still supplies every algorithm
(the noop just sits idle).

Phase 3's `simple-provider-adapter` (separate component) replaces
this with a real Layer-2 implementation that delegates to a
`tegmentum:key-backend` (e.g., the pkcs11-bridge).
