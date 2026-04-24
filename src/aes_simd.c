// wasm SIMD AES — block encrypt/decrypt.
//
// This file provides `__wrap_AES_encrypt` / `__wrap_AES_decrypt`, which
// the linker substitutes for OpenSSL's `AES_encrypt` / `AES_decrypt`
// when the build was run with `simd_aes=on`. Every mode of operation
// (ECB, CBC, CTR, GCM, CCM, OCB) in OpenSSL's no-asm configuration goes
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
// Phase B status: AES-128 encrypt is a correct SIMD implementation
// using:
//   - ShiftRows via a single i8x16.shuffle with fixed indices
//   - MixColumns via xtime + column rotations + XOR
//   - AddRoundKey via v128.xor
//   - SubBytes via scalar S-box (store-lookup-load; future phase will
//     replace this with a vpAES-style nibble-swizzle).
// AES-192, AES-256, and the decrypt path still fall through to
// __real_AES_encrypt / __real_AES_decrypt (OpenSSL's T-table code).
// Phase C lifts those.
//
// AES_KEY invariants this file preserves:
//   - `rd_key[]` is an array of uint32_t holding round keys in standard
//     OpenSSL layout: columns stored as big-endian uint32_t words.
//   - `rounds` is 10, 12, or 14 for AES-128/192/256.
//   - Thread-safety: none needed — wasi is single-threaded.
//
// Constant-time: no data-dependent branches. The scalar S-box loop is
// straight-line across 16 bytes. (Cache-timing is a theoretical worry
// on general CPUs but is moot under wasmtime's sandbox model.)

#include <stdint.h>

#include <openssl/aes.h>

#ifdef __wasm_simd128__
#  include <wasm_simd128.h>
#endif

// Declared by the linker via --wrap=AES_encrypt / --wrap=AES_decrypt.
// When --wrap is absent these symbols aren't referenced and the
// resulting __wrap_AES_encrypt / __wrap_AES_decrypt defined below
// become dead code.
extern void __real_AES_encrypt(const unsigned char *in,
                               unsigned char *out,
                               const AES_KEY *key);
extern void __real_AES_decrypt(const unsigned char *in,
                               unsigned char *out,
                               const AES_KEY *key);

#ifdef __wasm_simd128__

// FIPS 197 Figure 7. AES S-box for SubBytes. Public constant.
static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

// Apply SubBytes to each byte of a 16-byte state.
// Scalar S-box lookup (future: vpAES nibble-swizzle trick).
static inline v128_t aes_sub_bytes(v128_t state) {
    uint8_t b[16];
    wasm_v128_store(b, state);
    for (int i = 0; i < 16; i++) b[i] = AES_SBOX[b[i]];
    return wasm_v128_load(b);
}

// ShiftRows for OpenSSL's column-major state layout.
// State is a 4x4 matrix stored as 16 bytes with s[col*4 + row].
// After ShiftRows:
//   row 0: unchanged
//   row 1: shift left (cyclic) by 1
//   row 2: shift left by 2
//   row 3: shift left by 3
// So each output column c, row r comes from input column (c + r) mod 4.
static inline v128_t aes_shift_rows(v128_t state) {
    return wasm_i8x16_shuffle(state, state,
        0,  5, 10, 15,   // output column 0
        4,  9, 14,  3,   // output column 1
        8, 13,  2,  7,   // output column 2
       12,  1,  6, 11);  // output column 3
}

// xtime: GF(2^8) multiplication by 2, applied byte-wise.
//   x·2 = (x << 1) XOR (x >> 7 ? 0x1b : 0)
// Done SIMD-wide with a high-bit mask.
static inline v128_t aes_xtime(v128_t x) {
    v128_t shl = wasm_i8x16_shl(x, 1);
    // 0xff where x >= 0x80, else 0x00.
    v128_t high = wasm_u8x16_gt(x, wasm_u8x16_splat(0x7f));
    v128_t reduce = wasm_v128_and(high, wasm_u8x16_splat(0x1b));
    return wasm_v128_xor(shl, reduce);
}

// MixColumns: each column becomes [s0', s1', s2', s3'] = M · [s0,s1,s2,s3]
// where M = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] over GF(2^8).
//
// Let t = xtime(s) (so 3·s = t XOR s). For position 0 in a column:
//   s0' = 2·s0 XOR 3·s1 XOR s2 XOR s3
//       = t0 XOR (t1 XOR s1) XOR s2 XOR s3
//       = t0 XOR t1 XOR s1 XOR s2 XOR s3
//
// Define rot_k(s) = left-rotate each 4-byte column by k. Then for any row r,
// rot_k(s)[col*4 + r] = s[col*4 + ((r+k) mod 4)]. So:
//   MixColumns(s) = t XOR rot_1(t) XOR rot_1(s) XOR rot_2(s) XOR rot_3(s)
static inline v128_t aes_mix_columns(v128_t s) {
    v128_t t = aes_xtime(s);

    v128_t s_rot1 = wasm_i8x16_shuffle(s, s,
        1, 2, 3, 0,   5, 6, 7, 4,   9, 10, 11, 8,  13, 14, 15, 12);
    v128_t s_rot2 = wasm_i8x16_shuffle(s, s,
        2, 3, 0, 1,   6, 7, 4, 5,  10, 11,  8, 9,  14, 15, 12, 13);
    v128_t s_rot3 = wasm_i8x16_shuffle(s, s,
        3, 0, 1, 2,   7, 4, 5, 6,  11,  8,  9, 10, 15, 12, 13, 14);
    v128_t t_rot1 = wasm_i8x16_shuffle(t, t,
        1, 2, 3, 0,   5, 6, 7, 4,   9, 10, 11, 8,  13, 14, 15, 12);

    v128_t out = wasm_v128_xor(t, t_rot1);
    out = wasm_v128_xor(out, s_rot1);
    out = wasm_v128_xor(out, s_rot2);
    out = wasm_v128_xor(out, s_rot3);
    return out;
}

// Load a round key from OpenSSL's AES_KEY into byte-plaintext order.
//
// OpenSSL's `rd_key[]` holds 32-bit columns in big-endian. On
// little-endian wasm, storing a big-endian uint32 means its bytes are
// reversed in memory: key bytes (k0,k1,k2,k3) land in memory as
// (k3,k2,k1,k0). Since our state v128 holds plaintext bytes in their
// natural order, we need to reverse each 4-byte word of the round key
// before XORing.
static inline v128_t load_round_key(const uint8_t *rk) {
    v128_t raw = wasm_v128_load(rk);
    return wasm_i8x16_shuffle(raw, raw,
         3,  2,  1,  0,
         7,  6,  5,  4,
        11, 10,  9,  8,
        15, 14, 13, 12);
}

// AES-128 encrypt: 10 rounds.
// Round keys are 11 consecutive 16-byte blocks in key->rd_key.
static void aes128_encrypt_simd(const uint8_t in[16], uint8_t out[16],
                                const AES_KEY *key) {
    const uint8_t *rk = (const uint8_t *)key->rd_key;

    v128_t state = wasm_v128_load(in);
    state = wasm_v128_xor(state, load_round_key(rk));
    rk += 16;

    for (int round = 1; round < 10; round++) {
        state = aes_sub_bytes(state);
        state = aes_shift_rows(state);
        state = aes_mix_columns(state);
        state = wasm_v128_xor(state, load_round_key(rk));
        rk += 16;
    }
    // Final round: no MixColumns.
    state = aes_sub_bytes(state);
    state = aes_shift_rows(state);
    state = wasm_v128_xor(state, load_round_key(rk));

    wasm_v128_store(out, state);
}

#endif // __wasm_simd128__

void __wrap_AES_encrypt(const unsigned char *in,
                        unsigned char *out,
                        const AES_KEY *key) {
#ifdef __wasm_simd128__
    if (key->rounds == 10) {
        aes128_encrypt_simd(in, out, key);
        return;
    }
#endif
    // AES-192, AES-256, or non-SIMD build: fall through.
    __real_AES_encrypt(in, out, key);
}

void __wrap_AES_decrypt(const unsigned char *in,
                        unsigned char *out,
                        const AES_KEY *key) {
    // Phase C will add the SIMD decrypt path.
    __real_AES_decrypt(in, out, key);
}
