# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), with
versions tracked via git tags (`v0.1.0`, `v0.2.0`, …).

## [Unreleased]

### Changed
- Toolchain bump: build OpenSSL with wasi-sdk 33 (was 32) and run the
  Rust host/fuzz crates against wasmtime 44.0.2 (was 44.0.0).

## [0.1.0] - 2026-04-24

First tagged release. OpenSSL 3.6.2 compiled to a `wasm32-wasip2`
component, callable from wasmtime ≥ 44 through a curated WIT surface.

### Added
- Component surface covering `error`, `random`, `bignum`, `digest`,
  `mac`, `cipher`, `kdf`, `pkey`, `x509`, `tls` (256 exports total).
- `pkey.keygen-params.dh-named(dh-group)` — DH keygen against
  standardized safe primes (RFC 7919 `ffdhe2048…ffdhe8192`,
  RFC 3526 `modp2048…modp8192`). No prime search, so keygen is
  bounded by one modular exponentiation instead of a full
  Miller-Rabin search. A full 2-party FFDHE-2048 agreement test
  runs in ~15 s on wasm (vs. 5+ minutes for the fresh-params path,
  which stays available as `pkey.keygen-params.dh(dh-keygen)` for
  the few callers who actually want it).
- `tls` client and server with TLS 1.2 / 1.3, ALPN, SNI, session
  tickets, keylog (wired through `SSL_CTX_set_keylog_callback` and
  drainable per client/server resource), and system-CA chain
  validation. Verified live against `example.com:443`.
- 104 host-side tests across 22 suites in `examples/host/tests/`,
  including NIST/RFC/FIPS 197 known-answer vectors and a 1000-round
  differential against native libssl for AES.
- `examples/https-fetch/` and `examples/sign-service/` demo apps.
- Criterion benchmark harness (`examples/host/benches/`) comparing
  the component against native OpenSSL.
- `make dev` one-command setup (install wasi-sdk, fetch CA bundle,
  build, test).
- Experimental `make simd_aes=on` knob that replaces OpenSSL's
  T-table `AES_encrypt` / `AES_decrypt` with hand-written wasm SIMD
  via linker `--wrap`. AES-128/192/256 encrypt and decrypt,
  validated against FIPS 197 and CAVP vectors. Currently ~40%
  slower than the T-table baseline on AES-256-GCM (64 KiB); a
  vpAES nibble-swizzle S-box would close the gap but is not
  in-tree (see `src/aes_vpaes_todo.md`). Default off.
- `make simd=on` enables `-msimd128` (modest SHA-256 speedup, no
  measurable AES speedup without hand-written intrinsics).
- `make size=min` disables legacy cipher/digest families (RIPEMD,
  BLAKE2, SM*, Camellia, ARIA, IDEA, RC*, SEED, MDC2, Whirlpool,
  Cast, Blowfish). Saves ~230 KiB (6% of the default 3.65 MiB
  artifact).
- `make check` runs clang's static analyzer plus wasm validation.
- `make repro-check` verifies bit-reproducible builds by building
  twice from scratch and comparing.
- `scripts/install-wasi-sdk.sh` fetches wasi-sdk 32 into
  `.wasi-sdk/`.
- `scripts/fetch-mozilla-ca.sh` vendors curl.se's Mozilla CA
  bundle.
- `scripts/gen-sbom.sh` emits CycloneDX 1.5 SBOM covering OpenSSL,
  wasi-sdk, and clang versions.
- CI workflows: push/PR build-and-test matrix (Linux + macOS),
  `cargo audit` against all host-side lockfiles, weekly benchmark
  and fuzz runs.
- `cargo fuzz` skeleton with five libfuzzer targets.

### Fixed
- `cipher.algorithm.sm4-gcm` previously returned
  `unsupported-algorithm` because OpenSSL 3.x has no
  `EVP_sm4_gcm()` accessor. Now resolved via cached
  `EVP_CIPHER_fetch("SM4-GCM")`.

### Known limitations
- DTLS 1.2 is in the WIT enum but not implemented. The component
  rejects DTLS-only protocol ranges with
  `TlsError::ProtocolVersion` rather than silently falling back to
  TLS.
- TLS server tests need `--test-threads=1` (implicit via criterion
  serial binding).
- DH 2048-bit fresh-parameter generation (the
  `pkey.keygen-params.dh(...)` path) is slow (>2 min per call on
  wasm); the regression test is `#[ignore]` by default. Real
  deployments should use `dh-named` against an RFC 7919 / RFC 3526
  group instead — that path is fast enough for CI.
- Portable-C AES is ~120× slower than native AES-NI. The SIMD AES
  opt-in path is correctness-complete but not yet a speed-up; see
  `README.md` § Wasm SIMD AES for the open work.

## Versioning

The WIT surface is pre-1.0. Breaking changes to `wit/*.wit` may land
on any minor release until a stable `v1.0.0` tag. The exported package
`openssl:component@0.1.0` will bump in lockstep.
