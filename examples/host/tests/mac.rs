//! HMAC/CMAC/Poly1305 known-answer tests.

use openssl_wasm_host::{Fixture, exports, hex};
use exports::openssl::component::digest::Algorithm;
use exports::openssl::component::mac::{self, HmacParams, CmacParams, BlockCipher, Params};

#[tokio::test]
async fn hmac_sha256_rfc4231_case1() {
    // RFC 4231 §4.2.
    let mut f = Fixture::new().await.unwrap();
    let tag = f.bindings.openssl_component_mac()
        .call_one_shot(&mut f.store,
            mac::Algorithm::Hmac,
            &vec![0x0b; 20],
            &b"Hi There".to_vec(),
            &Params::Hmac(HmacParams { hash: Algorithm::Sha256 }))
        .await.unwrap().unwrap();
    assert_eq!(hex(&tag),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

#[tokio::test]
async fn hmac_sha256_rfc4231_case4() {
    // RFC 4231 §4.5 — "partial truncated" vector, full 32-byte output.
    let mut f = Fixture::new().await.unwrap();
    let key: Vec<u8> = (1..=25u8).collect();
    let data = vec![0xcdu8; 50];
    let tag = f.bindings.openssl_component_mac()
        .call_one_shot(&mut f.store, mac::Algorithm::Hmac, &key, &data,
            &Params::Hmac(HmacParams { hash: Algorithm::Sha256 }))
        .await.unwrap().unwrap();
    assert_eq!(hex(&tag),
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
}

#[tokio::test]
async fn cmac_aes128_nist_sp800_38b() {
    // NIST SP 800-38B example — CMAC with AES-128 over 16 null bytes of
    // plaintext. Expected tag from the standard.
    let mut f = Fixture::new().await.unwrap();
    let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
    let msg = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
    let tag = f.bindings.openssl_component_mac()
        .call_one_shot(&mut f.store, mac::Algorithm::Cmac, &key, &msg,
            &Params::Cmac(CmacParams { cipher: BlockCipher::Aes128 }))
        .await.unwrap().unwrap();
    assert_eq!(hex(&tag), "070a16b46b4d4144f79bdd9dd04a287c");
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
        .collect()
}
