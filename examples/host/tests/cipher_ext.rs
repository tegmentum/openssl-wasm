//! Extended cipher coverage: CCM, OCB, XTS, ARIA, CTR, streaming.

use openssl_wasm_host::{Fixture, exports};
use exports::openssl::component::cipher as ciph;

#[tokio::test]
async fn aes_256_ccm_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x55u8; 32];
    let nonce = vec![0x66u8; 12];  // CCM L=3
    let pt = b"ccm message".to_vec();
    let sealed = f.bindings.openssl_component_cipher()
        .call_seal(&mut f.store, ciph::Algorithm::Aes256Ccm,
                   &key, &nonce, &vec![], &pt, 16).await.unwrap().unwrap();
    let opened = f.bindings.openssl_component_cipher()
        .call_open(&mut f.store, ciph::Algorithm::Aes256Ccm,
                   &key, &nonce, &vec![], &sealed.ciphertext, &sealed.tag)
        .await.unwrap().unwrap();
    assert_eq!(pt, opened);
}

#[tokio::test]
async fn aes_256_ocb_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x77u8; 32];
    let nonce = vec![0x88u8; 12];
    let aad = b"ocb aad".to_vec();
    let pt = b"ocb message".to_vec();
    let sealed = f.bindings.openssl_component_cipher()
        .call_seal(&mut f.store, ciph::Algorithm::Aes256Ocb,
                   &key, &nonce, &aad, &pt, 16).await.unwrap().unwrap();
    let opened = f.bindings.openssl_component_cipher()
        .call_open(&mut f.store, ciph::Algorithm::Aes256Ocb,
                   &key, &nonce, &aad, &sealed.ciphertext, &sealed.tag)
        .await.unwrap().unwrap();
    assert_eq!(pt, opened);
}

#[tokio::test]
async fn aes_128_xts_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    // XTS needs a 2x-size key (two independent halves).
    let mut key = vec![0x99u8; 16];
    key.extend_from_slice(&vec![0xaau8; 16]);
    let iv = vec![0xaau8; 16];
    let pt = b"exactly one AES block 16".to_vec();
    let ct = f.bindings.openssl_component_cipher()
        .call_encrypt(&mut f.store, ciph::Algorithm::Aes128Xts,
                      &key, Some(&iv), ciph::PaddingMode::None, &pt)
        .await.unwrap().unwrap();
    let got = f.bindings.openssl_component_cipher()
        .call_decrypt(&mut f.store, ciph::Algorithm::Aes128Xts,
                      &key, Some(&iv), ciph::PaddingMode::None, &ct)
        .await.unwrap().unwrap();
    assert_eq!(pt, got);
}

#[tokio::test]
async fn aria_256_gcm_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x33u8; 32];
    let nonce = vec![0x44u8; 12];
    let pt = b"aria".to_vec();
    let sealed = f.bindings.openssl_component_cipher()
        .call_seal(&mut f.store, ciph::Algorithm::Aria256Gcm,
                   &key, &nonce, &vec![], &pt, 16).await.unwrap().unwrap();
    let opened = f.bindings.openssl_component_cipher()
        .call_open(&mut f.store, ciph::Algorithm::Aria256Gcm,
                   &key, &nonce, &vec![], &sealed.ciphertext, &sealed.tag)
        .await.unwrap().unwrap();
    assert_eq!(pt, opened);
}

#[tokio::test]
async fn aes_256_ctr_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x10u8; 32];
    let iv = vec![0x20u8; 16];
    let pt = b"aes-ctr is a stream cipher, no padding".to_vec();
    let ct = f.bindings.openssl_component_cipher()
        .call_encrypt(&mut f.store, ciph::Algorithm::Aes256Ctr,
                      &key, Some(&iv), ciph::PaddingMode::None, &pt)
        .await.unwrap().unwrap();
    assert_eq!(ct.len(), pt.len());  // CTR is length-preserving
    let got = f.bindings.openssl_component_cipher()
        .call_decrypt(&mut f.store, ciph::Algorithm::Aes256Ctr,
                      &key, Some(&iv), ciph::PaddingMode::None, &ct)
        .await.unwrap().unwrap();
    assert_eq!(pt, got);
}

#[tokio::test]
async fn streaming_aes_gcm_with_aad_matches_one_shot() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0xabu8; 32];
    let nonce = vec![0xcdu8; 12];
    let aad = b"streamed aad".to_vec();
    let pt = b"streamed plaintext split across multiple update calls".to_vec();

    // One-shot reference.
    let reference = f.bindings.openssl_component_cipher()
        .call_seal(&mut f.store, ciph::Algorithm::Aes256Gcm,
                   &key, &nonce, &aad, &pt, 16).await.unwrap().unwrap();

    // Streaming encryptor.
    let enc = f.bindings.openssl_component_cipher().encryptor()
        .call_constructor(&mut f.store, ciph::Algorithm::Aes256Gcm,
                          &key, Some(&nonce), ciph::PaddingMode::None)
        .await.unwrap();
    f.bindings.openssl_component_cipher().encryptor()
        .call_set_aad(&mut f.store, enc, &aad).await.unwrap().unwrap();
    let (a, b) = pt.split_at(pt.len() / 2);
    let c1 = f.bindings.openssl_component_cipher().encryptor()
        .call_update(&mut f.store, enc, &a.to_vec()).await.unwrap().unwrap();
    let c2 = f.bindings.openssl_component_cipher().encryptor()
        .call_update(&mut f.store, enc, &b.to_vec()).await.unwrap().unwrap();
    let (tail, tag) = f.bindings.openssl_component_cipher().encryptor()
        .call_finish(&mut f.store, enc).await.unwrap().unwrap();
    let mut ct = Vec::new();
    ct.extend_from_slice(&c1);
    ct.extend_from_slice(&c2);
    ct.extend_from_slice(&tail);
    assert_eq!(ct, reference.ciphertext);
    assert_eq!(tag.unwrap(), reference.tag);
}

#[tokio::test]
async fn streaming_cbc_decrypt_with_pkcs7() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x77u8; 32];
    let iv = vec![0x33u8; 16];
    let pt = b"pkcs7 padded through streaming decryption".to_vec();
    let ct = f.bindings.openssl_component_cipher()
        .call_encrypt(&mut f.store, ciph::Algorithm::Aes256Cbc,
                      &key, Some(&iv), ciph::PaddingMode::Pkcs7, &pt)
        .await.unwrap().unwrap();

    let dec = f.bindings.openssl_component_cipher().decryptor()
        .call_constructor(&mut f.store, ciph::Algorithm::Aes256Cbc,
                          &key, Some(&iv), ciph::PaddingMode::Pkcs7)
        .await.unwrap();
    let p1 = f.bindings.openssl_component_cipher().decryptor()
        .call_update(&mut f.store, dec, &ct).await.unwrap().unwrap();
    let tail = f.bindings.openssl_component_cipher().decryptor()
        .call_finish(&mut f.store, dec).await.unwrap().unwrap();
    let mut got = Vec::new();
    got.extend_from_slice(&p1);
    got.extend_from_slice(&tail);
    assert_eq!(got, pt);
}
