# Contributing to openssl-wasm

## Getting set up

```sh
git submodule update --init --recursive
scripts/install-wasi-sdk.sh   # downloads wasi-sdk 32 into .wasi-sdk/
make                          # builds build/openssl-component.wasm
make test                     # runs cargo test against the component
make check                    # static analysis + wasm validation
```

For editor support:

```sh
make compile-commands         # writes compile_commands.json for clangd
```

## How the pipeline fits together

```
wit/*.wit               (you write)
   │
   ▼
wit-bindgen c           → src/bindings/openssl.{c,h} (generated each build)
   │
   ▼
scripts/gen-stubs.sh    → src/stubs.c  (error-returning stubs for any
   │                                     WIT export not handled by a
   │                                     hand-written src/*.c)
   ▼
clang (wasi-sdk) src/*.c → build/obj/*.o
   │
   ▼
wasm-ld + libssl.a + libcrypto.a → build/openssl-component.wasm
```

## Adding a new WIT interface

Say you want to add a `hash-chain` interface that maintains a Merkle-tree
accumulator.

1. **Write the WIT.** Add `wit/hash-chain.wit`:

   ```wit
   package openssl:component@0.1.0;

   interface hash-chain {
       // Types, resources, functions.
   }
   ```

2. **Wire into the world.** Edit `wit/world.wit`:

   ```wit
   world openssl {
       // ...
       export hash-chain;
   }
   ```

3. **Inspect the generated header.** Run `make bindings` and look at
   `src/bindings/openssl.h`. Search for `exports_openssl_component_hash_chain_*`
   — those are the C functions you must implement.

4. **Write the glue.** Create `src/hash_chain.c` following the pattern
   of the existing files:

   ```c
   #include "bindings/openssl.h"
   #include "include/support.h"
   // #include relevant openssl/*.h headers

   bool exports_openssl_component_hash_chain_<fn>(...) {
       // map WIT args → OpenSSL calls → WIT return shape
   }

   void exports_openssl_component_hash_chain_<resource>_destructor(
           exports_openssl_component_hash_chain_<resource>_t *rep) {
       // free the rep
   }
   ```

5. **Build and test.** `make` rebuilds; any functions you didn't
   implement get auto-stubbed. Then add a test in
   `examples/host/tests/hash_chain.rs` using the `Fixture` helper.

## Critical gotchas

- **`own_X_t.__handle` is a u32, not a pointer.** To get the rep you
  passed into `_new()`, call `exports_..._X_rep(handle)`. Casting the
  handle to a pointer will compile, produce garbage, and fail silently
  in a deep OpenSSL call.
- **Ed25519 / Ed448 take `NULL` digest in `X509_sign()` and
  `EVP_DigestSignInit()`.** Detect the key type via
  `EVP_PKEY_get_base_id()` and pass NULL md for those. Other key
  types take an explicit digest.
- **`XStr_PARAM_construct_utf8_string` takes a pointer.** The buffer
  must outlive the param array. Literal strings and statically
  allocated names are fine; stack-local buffers are a bug waiting to
  happen.
- **`ERR_clear_error()` discipline.** If your code calls OpenSSL
  functions that may push errors on internal probes (e.g.
  `EVP_PKEY_get_raw_private_key` returning 0), clear the error queue
  before returning so the caller doesn't see phantom errors.
- **`wasm32-wasip2` emits a component directly.** Never run
  `wasm-tools component new` on our link output — it's already a
  component (magic `0d 00 01 00`).
- **`-mexec-model=reactor`** in the linker — otherwise the component
  grows a phantom `wasi:cli/run` export.

## LSP diagnostics

`clangd` will complain about `bindings/openssl.h` not being found
until `make bindings` has generated it. Run `make compile-commands`
after that, and your editor will resolve includes properly.

## Before submitting a PR

```sh
make                          # clean build succeeds
make test                     # all tests pass
make check                    # static analysis clean
make lint                     # clippy + rustfmt clean (examples/host)
```

CI runs the equivalent on Ubuntu. If your change affects TLS or x509
paths, make sure the tests in `examples/host/tests/tls.rs` and
`examples/host/tests/x509*.rs` still pass — those exercise the trickiest
code.

## Licensing and attribution

By contributing you agree your changes are licensed the same as the
rest of the repo. Do not copy code from other OpenSSL bindings projects
without checking their licenses first. Commits should use conventional-commits
format (`feat:`, `fix:`, `test:`, `docs:`, `ci:`) and should NOT include
tool/attribution lines.
