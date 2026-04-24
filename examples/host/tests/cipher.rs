//! AEAD + block-cipher round-trip tests.

use openssl_wasm_host::{Fixture, exports};
use exports::openssl::component::cipher as ciph;

#[tokio::test]
async fn aes_256_gcm_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x42u8; 32];
    let nonce = vec![0x24u8; 12];
    let aad = b"associated".to_vec();
    let pt = b"openssl inside wasm".to_vec();
    let sealed = f.bindings.openssl_component_cipher()
        .call_seal(&mut f.store, ciph::Algorithm::Aes256Gcm,
                   &key, &nonce, &aad, &pt, 16).await.unwrap().unwrap();
    let opened = f.bindings.openssl_component_cipher()
        .call_open(&mut f.store, ciph::Algorithm::Aes256Gcm,
                   &key, &nonce, &aad, &sealed.ciphertext, &sealed.tag)
        .await.unwrap().unwrap();
    assert_eq!(pt, opened);
}

#[tokio::test]
async fn chacha20_poly1305_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x11u8; 32];
    let nonce = vec![0x22u8; 12];
    let pt = b"quick brown fox".to_vec();
    let sealed = f.bindings.openssl_component_cipher()
        .call_seal(&mut f.store, ciph::Algorithm::Chacha20Poly1305,
                   &key, &nonce, &vec![], &pt, 16).await.unwrap().unwrap();
    let opened = f.bindings.openssl_component_cipher()
        .call_open(&mut f.store, ciph::Algorithm::Chacha20Poly1305,
                   &key, &nonce, &vec![], &sealed.ciphertext, &sealed.tag)
        .await.unwrap().unwrap();
    assert_eq!(pt, opened);
}

#[tokio::test]
async fn aead_tag_tamper_rejected() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x42u8; 32];
    let nonce = vec![0x24u8; 12];
    let pt = b"secret".to_vec();
    let sealed = f.bindings.openssl_component_cipher()
        .call_seal(&mut f.store, ciph::Algorithm::Aes256Gcm,
                   &key, &nonce, &vec![], &pt, 16).await.unwrap().unwrap();
    let mut bad_tag = sealed.tag.clone();
    bad_tag[0] ^= 0x01;
    let open = f.bindings.openssl_component_cipher()
        .call_open(&mut f.store, ciph::Algorithm::Aes256Gcm,
                   &key, &nonce, &vec![], &sealed.ciphertext, &bad_tag)
        .await.unwrap();
    assert!(open.is_err(), "tampered tag must not verify");
}

#[tokio::test]
async fn aes_256_cbc_pkcs7_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x33u8; 32];
    let iv = vec![0x44u8; 16];
    let pt = b"exactly 12.".to_vec();
    let ct = f.bindings.openssl_component_cipher()
        .call_encrypt(&mut f.store, ciph::Algorithm::Aes256Cbc,
                      &key, Some(&iv),
                      ciph::PaddingMode::Pkcs7, &pt)
        .await.unwrap().unwrap();
    let got = f.bindings.openssl_component_cipher()
        .call_decrypt(&mut f.store, ciph::Algorithm::Aes256Cbc,
                      &key, Some(&iv), ciph::PaddingMode::Pkcs7, &ct)
        .await.unwrap().unwrap();
    assert_eq!(pt, got);
}
