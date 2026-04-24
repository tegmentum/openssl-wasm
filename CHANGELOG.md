# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), with
versions tracked via git tags (`v0.1.0`, `v0.2.0`, …).

## [Unreleased]

### Added
- `make dev` one-command setup (install wasi-sdk, fetch CA bundle,
  build, test).
- Experimental `make simd_aes=on` knob that replaces OpenSSL's T-table
  `AES_encrypt` / `AES_decrypt` with hand-written wasm SIMD via linker
  `--wrap`. AES-128/192/256 encrypt and decrypt, validated against
  FIPS 197 and CAVP vectors. Currently ~40% slower than the T-table
  baseline on AES-256-GCM (64 KiB); the vpAES nibble-swizzle S-box
  work that would close the gap is not yet in-tree. Default is off.
- Initial component surface covering `error`, `random`, `bignum`,
  `digest`, `mac`, `cipher`, `kdf`, `pkey`, `x509`, `tls`.
- `scripts/install-wasi-sdk.sh` fetches wasi-sdk 32 into `.wasi-sdk/`.
- `scripts/fetch-mozilla-ca.sh` vendors curl.se's Mozilla CA bundle.
- `scripts/gen-sbom.sh` emits CycloneDX 1.5 SBOM covering OpenSSL +
  wasi-sdk + clang versions.
- `make repro-check` verifies bit-reproducible builds by building twice
  from scratch and comparing.
- `make check` runs clang's static analyzer plus wasm validation.
- `make simd=on` enables `-msimd128` (modest SHA-256 speedup, no AES
  speedup without hand-written intrinsics).
- `make size=min` disables legacy cipher/digest families (RIPEMD,
  BLAKE2, SM*, Camellia, ARIA, IDEA, RC*, SEED, MDC2, Whirlpool, Cast,
  Blowfish). Saves ~230 KiB (6% of the default 3.65 MiB artifact).
- `examples/https-fetch/` and `examples/sign-service/` demo apps.
- Criterion benchmark harness comparing component vs native OpenSSL.

### Known limitations
- DTLS 1.2 is in the WIT enum but not implemented. The component
  rejects DTLS-only protocol ranges with `TlsError::ProtocolVersion`
  rather than silently falling back to TLS.
- TLS server tests need `--test-threads=1` (implicit via criterion
  serial binding).
- DH 2048-bit keygen is slow (>2 min per call on wasm); the test is
  `#[ignore]` by default.
- Keylog callback isn't wired to OpenSSL's `SSL_CTX_set_keylog_callback`
  yet; the resource exists but drain always returns empty.
- Portable-C AES is ~120× slower than native AES-NI; closing the gap
  needs hand-written wasm SIMD AES, not yet in-tree.

## Versioning

The WIT surface is pre-1.0. Breaking changes to `wit/*.wit` may land
on any minor release until a stable `v1.0.0` tag. The exported package
`openssl:component@0.1.0` will bump in lockstep.
