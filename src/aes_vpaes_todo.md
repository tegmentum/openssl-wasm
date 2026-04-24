# Phase E design note — vpAES full port

## Status

Phase E attempted and abandoned without code. This file documents what
was learned so the next attempt doesn't start from zero.

## Why Phase C's "drop-in vpAES S-box" doesn't work

The intuition that we could replace just `aes_sub_bytes` in `aes_simd.c`
with a vpAES-style nibble-swizzle S-box (leaving the existing
`aes_shift_rows`, `aes_mix_columns`, and round-key XOR intact) is
attractive but wrong. I traced `S(0x00)` and `S(0x01)` by hand through
the pipeline `ipt → inv → sbo` and got `0x00` / `0x1F` instead of
`0x63` / `0x7C`. The reason:

- `ipt` is the input transform from AES basis into vpAES's internal
  basis *and also* unwinds the AES "pre-affine" component of the
  S-box.
- `sbo` is the output transform that re-applies the AES affine *and*
  moves back to AES basis.
- But `sb1`/`sb2` (used in the middle rounds) fuse the S-box with
  *InvMixColumns* contributions. Those tables don't produce a
  standalone S-box output; they produce the partial terms needed
  for MixColumns to work in vpAES basis.

Consequence: vpAES's state is **never** in AES basis between rounds.
It goes from AES basis once (via `ipt` at the start) into internal
basis, stays there through all rounds, and comes back once (via
`sbo` at the final round).

This means we can't cleanly slot a vpAES S-box into the Phase C
standard-basis framework. The entire encrypt/decrypt state machine
must be in vpAES basis, and round keys must be in vpAES basis, which
means the key schedule must run in vpAES basis too. The whole
algorithm is entangled.

## What a real Phase E requires

End-to-end port of `third_party/openssl/crypto/aes/asm/vpaes-x86_64.pl`:

1. **Wrap `AES_set_encrypt_key`** → port `_vpaes_schedule_core` for
   AES-128/192/256 so the produced round keys are in vpAES basis.
   The standard AES key schedule uses the S-box itself, so just
   post-processing OpenSSL's output via `ipt` doesn't work — the
   round keys for rounds ≥ 1 differ in value, not just representation.

2. **Wrap `AES_set_decrypt_key`** → port the decrypt variant (uses
   different mangle tables: `dksd`, `dksb`, `dkse`, `dks9`).

3. **Wrap `AES_encrypt`** → port `_vpaes_encrypt_core` (~75 lines of
   asm → equivalent wasm SIMD C). Key registers:
     - xmm9  = 0x0F splat (`k_s0F`)
     - xmm10 = `k_inv` (tower-field inverse table)
     - xmm11 = `k_inv+16` (`inva`, "inverse assistant")
     - xmm12 = `k_sb1+16` (`sb1t`)
     - xmm13 = `k_sb1` (`sb1u`)
     - xmm14 = `k_sb2+16` (`sb2t`)
     - xmm15 = `k_sb2` (`sb2u`)
   The x86 `pshufb` maps to wasm's `i8x16.swizzle`; both treat
   high-bit-set indices as "output zero". The algorithm relies on
   this to propagate special values like 0x80 through lookup chains.

4. **Wrap `AES_decrypt`** → port `_vpaes_decrypt_core`. Uses `dipt`,
   `dsb9/dsbd/dsbb/dsbe/dsbo` tables.

5. **Validate** against the existing `examples/host/tests/aes_kat.rs`
   CAVP suite. The 1000-round differential against native libssl is
   particularly useful for catching edge cases.

## Data tables to extract

All in `third_party/openssl/crypto/aes/asm/vpaes-x86_64.pl` under
`_vpaes_consts`, as `.quad` values. Each `.quad` is 8 bytes
little-endian, so the table bytes come out with the first `.quad`
containing bytes [0..7] and the second [8..15].

Encrypt-side:
- `Lk_inv` (16 + 16 bytes): inv, inva
- `Lk_s0F` (16 bytes): 0x0F splat
- `Lk_ipt` (16 + 16): iptlo, ipthi
- `Lk_sb1` (16 + 16): sb1u, sb1t
- `Lk_sb2` (16 + 16): sb2u, sb2t
- `Lk_sbo` (16 + 16): sbou, sbot
- `Lk_mc_forward` (4 × 16): MixColumns shuffle patterns, indexed by round
- `Lk_mc_backward` (4 × 16)
- `Lk_sr` (4 × 16): ShiftRows shuffle patterns, indexed by round
- `Lk_rcon` (16): Rijndael rcon values
- `Lk_s63` (16): constant 0x63 splat (post-affine)
- `Lk_opt` (16 + 16): output transform for key schedule
- `Lk_deskew` (16 + 16): key-schedule deskew tables

Decrypt-side (additional):
- `Lk_dipt` (16 + 16): decrypt input transform
- `Lk_dsb9/dsbd/dsbb/dsbe/dsbo` (each 16 + 16): decrypt S-box
  composition tables
- `Lk_dksd/dksb/dkse/dks9` (each 16 + 16): decrypt key schedule

## Effort estimate

Honest budget: 8–12 hours of focused work. The algorithm is fiddly
and crypto-correct-or-wrong, so iterative validation against CAVP is
mandatory. Any shortcut risks shipping silent-wrong AES.

## Alternative: scalar S-box + inlined ShiftRows

A smaller win (maybe 20–30% vs T-tables, not the 3-5× vpAES promises)
is to fuse the scalar S-box with ShiftRows:

```c
static inline v128_t aes_sub_shift(v128_t state) {
    uint8_t b[16];
    wasm_v128_store(b, state);
    uint8_t out[16];
    out[0]  = AES_SBOX[b[0]];   out[1]  = AES_SBOX[b[5]];
    out[2]  = AES_SBOX[b[10]];  out[3]  = AES_SBOX[b[15]];
    out[4]  = AES_SBOX[b[4]];   out[5]  = AES_SBOX[b[9]];
    out[6]  = AES_SBOX[b[14]];  out[7]  = AES_SBOX[b[3]];
    out[8]  = AES_SBOX[b[8]];   out[9]  = AES_SBOX[b[13]];
    out[10] = AES_SBOX[b[2]];   out[11] = AES_SBOX[b[7]];
    out[12] = AES_SBOX[b[12]];  out[13] = AES_SBOX[b[1]];
    out[14] = AES_SBOX[b[6]];   out[15] = AES_SBOX[b[11]];
    return wasm_v128_load(out);
}
```

Eliminates one v128↔memory round trip per round (from two to one)
and fuses the ShiftRows shuffle into the scalar loop. Would require
benchmarking to confirm it actually helps, since modern compilers
may already schedule the two steps tightly.

If the vpAES budget isn't available, this is a cheaper intermediate
win worth measuring.
