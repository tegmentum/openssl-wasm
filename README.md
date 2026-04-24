# openssl-wasm

[![CI](https://github.com/tegmentum/openssl-wasm/actions/workflows/ci.yml/badge.svg)](https://github.com/tegmentum/openssl-wasm/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

OpenSSL 3.6.2 compiled as a WebAssembly Component (target `wasm32-wasip2`),
callable from a `wasmtime` host via a curated WIT surface.

The component is **real OpenSSL** — `third_party/openssl` is the upstream
source, built with `wasi-sdk` 32's clang into `libcrypto.a` + `libssl.a`
and statically linked into a wasm component. The C glue in `src/` maps
the WIT exports to OpenSSL's `EVP_*`, `X509_*`, `SSL_*`, etc. The only
Rust in the repo is the test driver in `examples/host`.

## Status

- All 256 WIT exports are implemented against real OpenSSL.
- 32 automated tests in `examples/host/tests/` pass, including
  NIST/RFC known-answer vectors.
- TLS client verified live against `example.com:443` with real
  certificate-chain validation against the system CA bundle.

## Interfaces (see `wit/`)

| Interface | Covers |
|-----------|--------|
| `error`   | ERR_get_error_all, describe, drain |
| `random`  | RAND_bytes / RAND_priv_bytes / RAND_add |
| `digest`  | MD5/SHA-1/SHA-2/SHA-3/SHAKE/BLAKE2/RIPEMD/SM3 one-shot + streaming + XOF |
| `mac`     | HMAC / CMAC / KMAC / Poly1305 / SipHash / GMAC |
| `cipher`  | AES (ECB/CBC/CTR/CFB/OFB/XTS/GCM/CCM/OCB), ChaCha20-Poly1305, Camellia, ARIA, 3DES, RC4 |
| `kdf`     | PBKDF2, HKDF, scrypt, Argon2, KBKDF, SSKDF, X9.63, TLS1.3-expand-label |
| `pkey`    | RSA / RSA-PSS / EC / Ed25519,Ed448 / X25519,X448 / DH — keygen, sign/verify, encrypt/decrypt, derive, PEM/DER/PKCS#8 |
| `x509`    | Certificates / CSRs / CRLs / Store / chain validation / PKCS#12 / CMS |
| `tls`     | TLS 1.2 / 1.3 client and server, ALPN, SNI, session tickets, keylog |
| `bignum`  | BIGNUM arithmetic |

## Layout

```
.
├── config/50-wasm.conf        # OpenSSL Configure target for wasm32-wasip2
├── scripts/
│   ├── install-wasi-sdk.sh    # downloads wasi-sdk 32 into .wasi-sdk/
│   └── gen-stubs.sh           # regenerates src/stubs.c (should be empty now)
├── third_party/openssl/       # submodule, pinned to openssl-3.6.2
├── wit/                       # Component Model interface definitions
│   ├── world.wit              # re-exports everything below
│   ├── error.wit random.wit bignum.wit digest.wit mac.wit
│   ├── cipher.wit kdf.wit pkey.wit x509.wit tls.wit
├── src/                       # C glue: WIT exports → OpenSSL calls
│   ├── component.c            # error, random, digest (+ streaming)
│   ├── mac.c kdf.c bignum.c cipher.c pkey.c
│   ├── x509.c                 # parse / info / verify / store / PKCS#12 / CMS sign+verify
│   ├── x509_build.c           # cert & CSR build-and-sign, PKCS#12 build, CMS encrypt/decrypt
│   ├── tls.c                  # client + server
│   └── include/               # shared helpers (support.h, algs.h)
├── examples/host/             # Rust wasmtime harness
│   ├── src/lib.rs             # Fixture + bindgen
│   ├── src/main.rs            # demo runner
│   └── tests/*.rs             # 9 suites, ~32 tests total
├── .github/workflows/ci.yml   # build + test on every push
└── Makefile
```

## Prerequisites

- **wasi-sdk 32.** `scripts/install-wasi-sdk.sh` drops it into `.wasi-sdk/`
  (gitignored). The Makefile picks that up automatically.
- **wasm-tools** and **wit-bindgen** (both from cargo). Tested with
  wasm-tools 1.247 and wit-bindgen 0.48.
- **wasmtime** runtime for the Rust host (44.x tested).
- **cargo / rustc** stable.

## Build

```sh
git submodule update --init --recursive
scripts/install-wasi-sdk.sh     # one-time, 200 MB download
make                            # → build/openssl-component.wasm (~3.8 MB)
make test                       # runs the full cargo test suite
make run                        # runs the demo binary against the component
```

Override wasi-sdk location: `WASI_SDK=/path/to/wasi-sdk make`.

## Using the component

From Rust with wasmtime 44:

```rust
wasmtime::component::bindgen!({
    world: "openssl",
    path: "wit",
    imports: { default: async },
    exports: { default: async },
});

// … instantiate, then call bindings.openssl_component_digest().call_one_shot(…)
```

See `examples/host/src/main.rs` and `examples/host/tests/*.rs` for
worked examples.

For TLS with certificate verification, grant the component `inherit_network()`,
`allow_ip_name_lookup(true)`, and preopen a directory containing a CA
bundle (`/etc/ssl/cert.pem` on macOS,
`/etc/ssl/certs/ca-certificates.crt` on Debian/Ubuntu).

## Design notes

- **Target:** `wasm32-wasip2`. wasi-sdk 32's clang emits a Component
  directly (magic bytes `0d 00 01 00`), so there's no `wasm-tools
  component new` step. We link with `-mexec-model=reactor` so the
  component exports only our WIT interfaces, no `wasi:cli/run`.
- **Disables at Configure time:** `no-threads`, `no-shared`, `no-dso`,
  `no-asm`, `no-engine`, `no-async`, `no-afalgeng`, `no-ktls`,
  `no-ui-console`, `no-autoload-config`, `no-module`, `no-apps`,
  `no-docs`, `no-quic`, `no-tests`, `OPENSSL_NO_UNIX_SOCK` (wasi-libc's
  `sockaddr_un` has no `sun_path`).
- **Sockets:** TLS is routed through wasi-libc's BSD socket shims,
  which forward to `wasi:sockets`. The host must grant socket permissions.
- **Filesystem:** CA bundle loading goes through `wasi:filesystem`.
  Preopen a directory, then call `store.load-from-file`.
- **RNG:** OpenSSL's DRBG is seeded via `getentropy`, backed by
  `wasi:random`.
- **Time:** certificate validity uses `wasi:clocks`.
- **setjmp/longjmp:** wasi-sdk 32 lowers these to Wasm exception
  handling. Wasmtime ≥ 40 has this enabled by default.

## Performance

Measured on an Apple M-series, wasmtime 44, opt-level=2 (see
`examples/host/benches/component_vs_native.rs`):

| Operation                     | Component       | Native (libssl) | Ratio |
|-------------------------------|----------------:|----------------:|------:|
| SHA-256 (1 MiB)               |       256 MiB/s |     2,384 MiB/s |   ~9× |
| AES-256-GCM seal (64 KiB)     |        52 MiB/s |     6,208 MiB/s | ~120× |
| Ed25519 sign (1 KiB msg)      |          360 µs |          31.5 µs|  ~11× |

Interpretation:
- SHA-256 and signatures are within an order of magnitude of native.
- AES-256-GCM is much slower because native uses AES-NI hardware
  instructions; the component runs OpenSSL's portable C implementation
  (`no-asm` at Configure).
- If you need high AEAD throughput, consider batching or picking
  ChaCha20-Poly1305 where both sides are pure software.

Run `cargo bench --manifest-path examples/host/Cargo.toml` to reproduce.

### Wasm SIMD

`make simd=on` turns on `-msimd128` during the OpenSSL build. Measured
effect on this workload:

| Operation                  | Baseline  | `simd=on` | Δ      |
|----------------------------|----------:|----------:|-------:|
| SHA-256 (1 MiB)            | 226 MiB/s | 242 MiB/s |   +7%  |
| AES-256-GCM seal (64 KiB)  |  41 MiB/s |  41 MiB/s |   0%   |
| Ed25519 sign               |    391 µs |    387 µs |  ~1%   |

Conclusion: modest SHA-256 improvement from clang's auto-vectorizer,
no material change on AES or elliptic curves.

### Wasm SIMD AES (experimental)

`make simd_aes=on` replaces OpenSSL's T-table `AES_encrypt` /
`AES_decrypt` with hand-written wasm SIMD implementations via linker
`--wrap`. Coverage: AES-128 / 192 / 256 encrypt and decrypt. Validated
against NIST FIPS-197 and CAVP ECBGFSbox / ECBKeySbox vectors plus a
1000-round differential against native libssl.

**Current state: correctness-complete but slower than T-tables.**

| Operation                  | T-table   | `simd_aes=on`| Δ        |
|----------------------------|----------:|-------------:|---------:|
| AES-256-GCM seal (64 KiB)  |  56 MiB/s |    34 MiB/s  |  -40%    |
| AES-256-GCM seal (1 KiB)   |  1.9 MiB/s|    1.8 MiB/s |   -2%    |

Why slower: the current S-box is a scalar 256-entry lookup (16 byte
loads per block), surrounded by v128↔memory round-trips. T-tables
avoid this by fusing SubBytes + ShiftRows + MixColumns into a single
4-way-indexed 32-bit table load per byte. Closing the gap requires
replacing the scalar S-box with a vpAES nibble-swizzle
(Hamburg 2009) — ~12 SIMD ops per block instead of 16 scalar
lookups. That work isn't in-tree yet.

Default: **off**. Enable only if you're iterating on the algorithm.

## Security notes

### Constant-time guarantees

Whatever constant-time properties OpenSSL's native implementation
provides are preserved — the glue passes buffers through unmodified
and doesn't perform data-dependent branching. Specifically:

**Believed constant-time in OpenSSL (and preserved here):**
- `digest.one-shot`, `digest.context.update/finish` — block-based,
  not data-dependent.
- `mac.*` — HMAC/CMAC/Poly1305/SipHash/GMAC all constant-time in
  OpenSSL.
- `cipher.*` for AES via constant-time software implementations when
  AES-NI isn't available (OpenSSL's default on wasm).
- `pkey.sign_*` / `pkey.verify_*` / `pkey.derive` for RSA/EC/Ed/X/DH.
- `cipher.open` tag verification (uses `CRYPTO_memcmp`).

**NOT constant-time — avoid with secret inputs:**
- `bignum.to-dec` / `bignum.to-hex` — base conversion is data-dependent.
- `bignum.from-dec` / `bignum.from-hex` — parsing branches on digits.
- `error.describe` — string formatting.
- `pkey.save-private` / `pkey.load-private` — ASN.1 encoding size
  leaks key size bits.
- Any RSA/EC operation on a public key that happens to be used for
  signing (the library doesn't know your intent).

### Threat model

- The component runs in a wasmtime sandbox. Memory corruption in
  OpenSSL cannot escape the sandbox.
- The component assumes the host-provided `wasi:random` is a secure
  CSPRNG. If the host is compromised or misconfigured (e.g., feeds
  `/dev/zero` as entropy), all key material is compromised.
- The component loads CA bundles via `wasi:filesystem`. A malicious
  host can substitute the bundle, so TLS trust is only as strong as
  the preopened directory.
- Wasm exception handling is used for `setjmp`/`longjmp` in libssl
  error paths. Wasmtime ≥ 40 handles this; older runtimes will trap.

### What this component does NOT protect against

- Timing side channels on the host CPU: the component runs on the host
  CPU, so any data-dependent timing in OpenSSL flows through wasm
  translation but is still observable.
- The host can read the component's linear memory at any time. Do not
  use this for key custody in adversarial-host scenarios.
- The component does not implement side-channel hardening (e.g.
  blinding) beyond what OpenSSL provides natively.

## Deliberate WIT-surface omissions

The WIT surface exposes OpenSSL's curated high-level APIs. Low-level
APIs that don't translate cleanly to the Component Model (BIO, ASN.1,
OSSL_PARAM, providers, engines, raw NID lookups) are not exported.
Callers that need those should add more WIT interfaces and glue
functions, rather than try to expose raw pointers.
