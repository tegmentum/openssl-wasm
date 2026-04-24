//! KDF known-answer tests.

use openssl_wasm_host::{Fixture, exports, hex};
use exports::openssl::component::digest::Algorithm;
use exports::openssl::component::kdf::{HkdfParams, HkdfExtractParams, HkdfExpandParams, Pbkdf2Params};

fn hx(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn hkdf_sha256_rfc5869_case1() {
    let mut f = Fixture::new().await.unwrap();
    let okm = f.bindings.openssl_component_kdf()
        .call_hkdf(&mut f.store,
            &hx("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            &HkdfParams {
                hash: Algorithm::Sha256,
                salt: Some(hx("000102030405060708090a0b0c")),
                info: hx("f0f1f2f3f4f5f6f7f8f9"),
            }, 42).await.unwrap().unwrap();
    assert_eq!(hex(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

#[tokio::test]
async fn hkdf_extract_then_expand_equals_one_shot() {
    let mut f = Fixture::new().await.unwrap();
    let ikm = hx("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hx("000102030405060708090a0b0c");
    let info = hx("f0f1f2f3f4f5f6f7f8f9");

    let one_shot = f.bindings.openssl_component_kdf()
        .call_hkdf(&mut f.store, &ikm,
            &HkdfParams { hash: Algorithm::Sha256,
                          salt: Some(salt.clone()), info: info.clone() }, 42)
        .await.unwrap().unwrap();

    let prk = f.bindings.openssl_component_kdf()
        .call_hkdf_extract(&mut f.store, &ikm,
            &HkdfExtractParams { hash: Algorithm::Sha256, salt: Some(salt) })
        .await.unwrap().unwrap();
    let okm = f.bindings.openssl_component_kdf()
        .call_hkdf_expand(&mut f.store, &prk,
            &HkdfExpandParams { hash: Algorithm::Sha256, info }, 42)
        .await.unwrap().unwrap();
    assert_eq!(one_shot, okm);
}

#[tokio::test]
async fn pbkdf2_sha256_rfc7914_case() {
    // RFC 7914 appendix A derived from "passwd"/"salt" with c=1, dkLen=64.
    let mut f = Fixture::new().await.unwrap();
    let dk = f.bindings.openssl_component_kdf()
        .call_pbkdf2(&mut f.store, &b"passwd".to_vec(),
            &Pbkdf2Params { hash: Algorithm::Sha256,
                            iterations: 1,
                            salt: b"salt".to_vec() }, 64)
        .await.unwrap().unwrap();
    assert_eq!(hex(&dk),
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");
}
