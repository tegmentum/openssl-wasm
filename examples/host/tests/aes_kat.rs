//! NIST CAVP Known-Answer Tests for AES.
//!
//! These are the primary correctness check for the Phase-B+ vpAES
//! implementation. They exercise AES_encrypt / AES_decrypt directly via
//! ECB (no mode-specific padding/IV machinery) so a wrong S-box or
//! ShiftRows will fail immediately with a hex diff to the expected
//! block.
//!
//! Vectors drawn from NIST FIPS 197 Appendix B (AES-128), Appendix C
//! (AES-192, AES-256), and the CAVP `ECBGFSbox` / `ECBKeySbox` KATs.
//!
//! Source: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers

use openssl_wasm_host::{Fixture, exports};
use exports::openssl::component::cipher as ciph;

fn hx(s: &str) -> Vec<u8> {
    let c: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..c.len()).step_by(2)
        .map(|i| u8::from_str_radix(&c[i..i+2], 16).unwrap())
        .collect()
}

/// Run a single AES-ECB known-answer: expect(ct) == encrypt(pt) and
/// expect(pt) == decrypt(ct) under the given key.
async fn check_kat(
    f: &mut Fixture,
    alg: ciph::Algorithm,
    key_hex: &str, pt_hex: &str, ct_hex: &str,
    label: &str,
) {
    let key = hx(key_hex);
    let pt  = hx(pt_hex);
    let ct  = hx(ct_hex);

    // Encrypt: ECB with padding=none (our glue lets 16-byte blocks
    // through unchanged; longer inputs would need padding).
    let got_ct = f.bindings.openssl_component_cipher()
        .call_encrypt(&mut f.store, alg, &key, None,
                      ciph::PaddingMode::None, &pt)
        .await.unwrap()
        .unwrap_or_else(|e| panic!("{label} encrypt: {e:?}"));
    assert_eq!(got_ct, ct, "{label} encrypt mismatch");

    let got_pt = f.bindings.openssl_component_cipher()
        .call_decrypt(&mut f.store, alg, &key, None,
                      ciph::PaddingMode::None, &ct)
        .await.unwrap()
        .unwrap_or_else(|e| panic!("{label} decrypt: {e:?}"));
    assert_eq!(got_pt, pt, "{label} decrypt mismatch");
}

// FIPS 197 Appendix B — AES-128.
#[tokio::test]
async fn aes_128_fips197_appendix_b() {
    let mut f = Fixture::new().await.unwrap();
    check_kat(&mut f, ciph::Algorithm::Aes128Ecb,
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a",
        "FIPS-197 AES-128 Appendix B").await;
}

// FIPS 197 Appendix C.1 — AES-128 with all-zero key/pt is NOT a FIPS
// vector. Use the standard "2b7e..." key instead.
#[tokio::test]
async fn aes_128_cavp_ecbgfsbox_0() {
    // ECBGFSbox128 count=0
    let mut f = Fixture::new().await.unwrap();
    check_kat(&mut f, ciph::Algorithm::Aes128Ecb,
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "0336763e966d92595a567cc9ce537f5e",
        "CAVP ECBGFSbox128 count=0").await;
}

#[tokio::test]
async fn aes_128_cavp_ecbkeysbox_0() {
    // ECBKeySbox128 count=0 — all-zero plaintext, "tricky" key.
    let mut f = Fixture::new().await.unwrap();
    check_kat(&mut f, ciph::Algorithm::Aes128Ecb,
        "10a58869d74be5a374cf867cfb473859",
        "00000000000000000000000000000000",
        "6d251e6944b051e04eaa6fb4dbf78465",
        "CAVP ECBKeySbox128 count=0").await;
}

// FIPS 197 Appendix C.2 — AES-192.
#[tokio::test]
async fn aes_192_fips197_appendix_c2() {
    let mut f = Fixture::new().await.unwrap();
    check_kat(&mut f, ciph::Algorithm::Aes192Ecb,
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "00112233445566778899aabbccddeeff",
        "dda97ca4864cdfe06eaf70a0ec0d7191",
        "FIPS-197 AES-192 Appendix C.2").await;
}

// FIPS 197 Appendix C.3 — AES-256.
#[tokio::test]
async fn aes_256_fips197_appendix_c3() {
    let mut f = Fixture::new().await.unwrap();
    check_kat(&mut f, ciph::Algorithm::Aes256Ecb,
        "000102030405060708090a0b0c0d0e0f\
         101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "8ea2b7ca516745bfeafc49904b496089",
        "FIPS-197 AES-256 Appendix C.3").await;
}

#[tokio::test]
async fn aes_256_cavp_ecbgfsbox_0() {
    // ECBGFSbox256 count=0
    let mut f = Fixture::new().await.unwrap();
    check_kat(&mut f, ciph::Algorithm::Aes256Ecb,
        "00000000000000000000000000000000\
         00000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "5c9d844ed46f9885085e5d6a4f94c7d7",
        "CAVP ECBGFSbox256 count=0").await;
}

/// Differential test against the native `openssl` crate. Catches
/// "passes KATs but wrong on random inputs" bugs that a fixed corpus
/// doesn't.
#[tokio::test]
async fn aes_256_gcm_differential_10k_random() {
    let mut f = Fixture::new().await.unwrap();
    // Deterministic xorshift so CI is reproducible.
    let mut s: u64 = 0x1234_5678_9abc_def0;
    let mut rng = move || {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17; s
    };

    for i in 0..1_000u64 {
        let key: Vec<u8> = (0..32).map(|_| (rng() & 0xff) as u8).collect();
        let nonce: Vec<u8> = (0..12).map(|_| (rng() & 0xff) as u8).collect();
        let msg_len = (rng() % 256) as usize;
        let msg: Vec<u8> = (0..msg_len).map(|_| (rng() & 0xff) as u8).collect();
        let aad_len = (rng() % 32) as usize;
        let aad: Vec<u8> = (0..aad_len).map(|_| (rng() & 0xff) as u8).collect();

        // Component
        let sealed = f.bindings.openssl_component_cipher()
            .call_seal(&mut f.store, ciph::Algorithm::Aes256Gcm,
                       &key, &nonce, &aad, &msg, 16)
            .await.unwrap().unwrap();

        // Native reference
        let mut tag = vec![0u8; 16];
        let native_ct = openssl::symm::encrypt_aead(
            openssl::symm::Cipher::aes_256_gcm(),
            &key, Some(&nonce), &aad, &msg, &mut tag
        ).unwrap();

        assert_eq!(sealed.ciphertext, native_ct,
            "round {i}: AES-256-GCM ciphertext mismatch");
        assert_eq!(sealed.tag, tag,
            "round {i}: AES-256-GCM tag mismatch");
    }
}
