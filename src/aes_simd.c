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
// Phase C status: full AES-128/192/256 encrypt and decrypt in SIMD.
// SubBytes / InvSubBytes still use scalar lookup; vpAES nibble-swizzle
// lands in Phase E.
//
// Algorithm notes:
//   - Decrypt uses the "Equivalent Inverse Cipher" (FIPS 197 §5.3.5),
//     which is what OpenSSL's AES_set_decrypt_key produces. Middle
//     round keys have already had InvMixColumns applied during key
//     expansion, so this file doesn't re-apply it.
//   - InvMixColumns computed as MixColumns(s) ⊕ 8·col_sum(s) ⊕
//     4·alt_sum(s), exploiting the identity
//       M_inv - M = 8·[1,1,1,1] + 4·[1,0,1,0]   (per column)
//     See commit message for the derivation.
//
// AES_KEY invariants preserved:
//   - `rd_key[]` holds 32-bit columns in big-endian (OpenSSL's native
//     layout). On little-endian wasm this means bytes land reversed
//     within each u32; `load_round_key` unreverses them.
//   - `rounds` is 10/12/14 for AES-128/192/256.
//
// Constant-time: no data-dependent branches. The scalar S-box loop is
// straight-line across 16 bytes.

#include <stdint.h>

#include <openssl/aes.h>

#ifdef __wasm_simd128__
#  include <wasm_simd128.h>
#endif

extern void __real_AES_encrypt(const unsigned char *in,
                               unsigned char *out,
                               const AES_KEY *key);
extern void __real_AES_decrypt(const unsigned char *in,
                               unsigned char *out,
                               const AES_KEY *key);

#ifdef __wasm_simd128__

// FIPS 197 Figure 7. AES S-box.
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

// FIPS 197 Figure 14. AES inverse S-box.
static const uint8_t AES_INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

static inline v128_t aes_sub_bytes(v128_t state) {
    uint8_t b[16];
    wasm_v128_store(b, state);
    for (int i = 0; i < 16; i++) b[i] = AES_SBOX[b[i]];
    return wasm_v128_load(b);
}

static inline v128_t aes_inv_sub_bytes(v128_t state) {
    uint8_t b[16];
    wasm_v128_store(b, state);
    for (int i = 0; i < 16; i++) b[i] = AES_INV_SBOX[b[i]];
    return wasm_v128_load(b);
}

// ShiftRows: row r shifts left by r (cyclic).
static inline v128_t aes_shift_rows(v128_t state) {
    return wasm_i8x16_shuffle(state, state,
        0,  5, 10, 15,
        4,  9, 14,  3,
        8, 13,  2,  7,
       12,  1,  6, 11);
}

// InvShiftRows: row r shifts right by r (cyclic). Inverse of aes_shift_rows.
static inline v128_t aes_inv_shift_rows(v128_t state) {
    return wasm_i8x16_shuffle(state, state,
        0, 13, 10,  7,
        4,  1, 14, 11,
        8,  5,  2, 15,
       12,  9,  6,  3);
}

// xtime: GF(2^8) multiplication by 2, byte-wise.
static inline v128_t aes_xtime(v128_t x) {
    v128_t shl = wasm_i8x16_shl(x, 1);
    v128_t high = wasm_u8x16_gt(x, wasm_u8x16_splat(0x7f));
    v128_t reduce = wasm_v128_and(high, wasm_u8x16_splat(0x1b));
    return wasm_v128_xor(shl, reduce);
}

// Column rotations (left-rotate each 4-byte column by 1, 2, 3).
static inline v128_t rot_col_1(v128_t s) {
    return wasm_i8x16_shuffle(s, s,
        1, 2, 3, 0,   5, 6, 7, 4,   9, 10, 11, 8,  13, 14, 15, 12);
}
static inline v128_t rot_col_2(v128_t s) {
    return wasm_i8x16_shuffle(s, s,
        2, 3, 0, 1,   6, 7, 4, 5,  10, 11,  8, 9,  14, 15, 12, 13);
}
static inline v128_t rot_col_3(v128_t s) {
    return wasm_i8x16_shuffle(s, s,
        3, 0, 1, 2,   7, 4, 5, 6,  11,  8,  9, 10, 15, 12, 13, 14);
}

// MixColumns. Derivation in the MixColumns section of the file header.
static inline v128_t aes_mix_columns(v128_t s) {
    v128_t t = aes_xtime(s);
    v128_t s_rot1 = rot_col_1(s);
    v128_t s_rot2 = rot_col_2(s);
    v128_t s_rot3 = rot_col_3(s);
    v128_t t_rot1 = rot_col_1(t);

    v128_t out = wasm_v128_xor(t, t_rot1);
    out = wasm_v128_xor(out, s_rot1);
    out = wasm_v128_xor(out, s_rot2);
    out = wasm_v128_xor(out, s_rot3);
    return out;
}

// InvMixColumns via the identity
//   M_inv(s) = M(s) ⊕ 8·col_sum(s) ⊕ 4·alt_sum(s)
// where col_sum = sum over each column of s (broadcast into every byte
// of that column), and alt_sum = s ⊕ rot_col_2(s).
//
// Derivation: M_inv - M is the matrix
//   [[12,  8, 12,  8],
//    [ 8, 12,  8, 12],
//    [12,  8, 12,  8],
//    [ 8, 12,  8, 12]]
// Each row is 8·[1,1,1,1] + 4·[1,0,1,0] (or 4·[0,1,0,1]), which is
// 8 times the column-sum plus 4 times alt_sum.
static inline v128_t aes_inv_mix_columns(v128_t s) {
    v128_t mc = aes_mix_columns(s);

    v128_t s_rot1 = rot_col_1(s);
    v128_t s_rot2 = rot_col_2(s);
    v128_t s_rot3 = rot_col_3(s);

    v128_t col_sum = wasm_v128_xor(s, s_rot1);
    col_sum = wasm_v128_xor(col_sum, s_rot2);
    col_sum = wasm_v128_xor(col_sum, s_rot3);

    v128_t alt_sum = wasm_v128_xor(s, s_rot2);

    // 4x = xtime(xtime(x)); 8x = xtime(xtime(xtime(x)))
    v128_t four_alt = aes_xtime(aes_xtime(alt_sum));
    v128_t eight_col = aes_xtime(aes_xtime(aes_xtime(col_sum)));

    v128_t m_diff = wasm_v128_xor(eight_col, four_alt);
    return wasm_v128_xor(mc, m_diff);
}

// Load a round key from OpenSSL's AES_KEY into byte-plaintext order.
// See file header for the byte-swap rationale.
static inline v128_t load_round_key(const uint8_t *rk) {
    v128_t raw = wasm_v128_load(rk);
    return wasm_i8x16_shuffle(raw, raw,
         3,  2,  1,  0,
         7,  6,  5,  4,
        11, 10,  9,  8,
        15, 14, 13, 12);
}

// Encrypt. Handles AES-128 (10 rounds), AES-192 (12), AES-256 (14).
static void aes_encrypt_simd(const uint8_t in[16], uint8_t out[16],
                             const AES_KEY *key) {
    const uint8_t *rk = (const uint8_t *)key->rd_key;
    const int rounds = key->rounds;

    v128_t state = wasm_v128_load(in);
    state = wasm_v128_xor(state, load_round_key(rk));
    rk += 16;

    for (int round = 1; round < rounds; round++) {
        state = aes_sub_bytes(state);
        state = aes_shift_rows(state);
        state = aes_mix_columns(state);
        state = wasm_v128_xor(state, load_round_key(rk));
        rk += 16;
    }
    state = aes_sub_bytes(state);
    state = aes_shift_rows(state);
    state = wasm_v128_xor(state, load_round_key(rk));

    wasm_v128_store(out, state);
}

// Decrypt using the Equivalent Inverse Cipher (FIPS 197 §5.3.5).
// OpenSSL's AES_set_decrypt_key has already reversed the round-key
// order and applied InvMixColumns to the middle round keys, so we
// consume rd_key in order and simply XOR.
static void aes_decrypt_simd(const uint8_t in[16], uint8_t out[16],
                             const AES_KEY *key) {
    const uint8_t *rk = (const uint8_t *)key->rd_key;
    const int rounds = key->rounds;

    v128_t state = wasm_v128_load(in);
    state = wasm_v128_xor(state, load_round_key(rk));
    rk += 16;

    for (int round = 1; round < rounds; round++) {
        state = aes_inv_sub_bytes(state);
        state = aes_inv_shift_rows(state);
        state = aes_inv_mix_columns(state);
        state = wasm_v128_xor(state, load_round_key(rk));
        rk += 16;
    }
    state = aes_inv_sub_bytes(state);
    state = aes_inv_shift_rows(state);
    state = wasm_v128_xor(state, load_round_key(rk));

    wasm_v128_store(out, state);
}

#endif // __wasm_simd128__

void __wrap_AES_encrypt(const unsigned char *in,
                        unsigned char *out,
                        const AES_KEY *key) {
#ifdef __wasm_simd128__
    if (key->rounds == 10 || key->rounds == 12 || key->rounds == 14) {
        aes_encrypt_simd(in, out, key);
        return;
    }
#endif
    __real_AES_encrypt(in, out, key);
}

void __wrap_AES_decrypt(const unsigned char *in,
                        unsigned char *out,
                        const AES_KEY *key) {
#ifdef __wasm_simd128__
    if (key->rounds == 10 || key->rounds == 12 || key->rounds == 14) {
        aes_decrypt_simd(in, out, key);
        return;
    }
#endif
    __real_AES_decrypt(in, out, key);
}
