// wasm SIMD AES — vpAES-style block encrypt/decrypt.
//
// This file provides `__wrap_AES_encrypt` / `__wrap_AES_decrypt`, which
// the linker substitutes for OpenSSL's `AES_encrypt` / `AES_decrypt` when
// the build was run with `simd_aes=on`. Every mode of operation (ECB,
// CBC, CTR, GCM, CCM, OCB) in OpenSSL's no-asm configuration goes
// through these two functions per-block, so wrapping is enough to lift
// all AES-based cipher throughput.
//
// Design reference:
//   Mike Hamburg, "Accelerating AES with Vector Permute Instructions"
//   CHES 2009 (https://shiftleft.org/papers/vector_aes/vector_aes.pdf).
//   Adaptation of SSSE3's `pshufb` to wasm's `i8x16.swizzle` is the
//   same idea — both are 16-byte byte-shuffle-by-index primitives.
//
//   Also inspired by the RustCrypto `aes` crate's wasm SIMD backend
//   (Apache-2.0); no code copied.
//
// Phase A (this file) is a pass-through stub: the wrap functions
// delegate to `__real_AES_encrypt` / `__real_AES_decrypt`. Subsequent
// phases replace the body with vpAES rounds. Behavior is bitwise
// identical to unwrapped OpenSSL, giving us a stable integration
// point to validate against NIST CAVP before changing algorithms.
//
// Key invariants this file preserves:
//   - `AES_KEY` layout is OpenSSL's. We consume `key->rd_key[]`
//     (round keys) and `key->rounds` (10/12/14 for 128/192/256).
//   - Constant-time: no data-dependent branches on `in` or `key`.
//   - Thread-safety: none needed — the wasi target is single-threaded.

#include <stdint.h>

#include <openssl/aes.h>

// This file is always compiled. When the build passes
// -Wl,--wrap=AES_encrypt -Wl,--wrap=AES_decrypt (i.e. simd_aes=on), the
// linker redirects callers of AES_encrypt/AES_decrypt to the wrappers
// below. When wrap flags are absent, `__wrap_AES_*` are dead code and
// --gc-sections drops them. OPENSSL_WASM_SIMD_AES is defined only with
// simd_aes=on so we can gate Phase-B+ bodies on it cheaply.

// Declared by the linker via --wrap=AES_encrypt / --wrap=AES_decrypt.
extern void __real_AES_encrypt(const unsigned char *in,
                               unsigned char *out,
                               const AES_KEY *key);
extern void __real_AES_decrypt(const unsigned char *in,
                               unsigned char *out,
                               const AES_KEY *key);

// Pass-through stubs — Phase A plumbing. Phase B+ will replace these
// bodies with vpAES rounds.
void __wrap_AES_encrypt(const unsigned char *in,
                        unsigned char *out,
                        const AES_KEY *key) {
    __real_AES_encrypt(in, out, key);
}

void __wrap_AES_decrypt(const unsigned char *in,
                        unsigned char *out,
                        const AES_KEY *key) {
    __real_AES_decrypt(in, out, key);
}
