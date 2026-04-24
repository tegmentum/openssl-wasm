//! pkey keygen/sign/verify/derive.

use openssl_wasm_host::{Fixture, exports};
use exports::openssl::component::digest::Algorithm;
use exports::openssl::component::pkey as pk;

#[tokio::test]
async fn ed25519_sign_verify_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let key = f.bindings.openssl_component_pkey().pkey()
        .call_generate(&mut f.store,
            pk::KeygenParams::Ed(pk::EdwardsCurve::Ed25519))
        .await.unwrap().unwrap();
    let msg = b"sign me".to_vec();
    let sig = f.bindings.openssl_component_pkey().pkey()
        .call_sign_message(&mut f.store, key, None, &msg, None)
        .await.unwrap().unwrap();
    let ok = f.bindings.openssl_component_pkey().pkey()
        .call_verify_message(&mut f.store, key, None, &msg, &sig, None)
        .await.unwrap().unwrap();
    assert!(ok);
    assert_eq!(sig.len(), 64);
}

#[tokio::test]
async fn ed25519_tamper_rejected() {
    let mut f = Fixture::new().await.unwrap();
    let key = f.bindings.openssl_component_pkey().pkey()
        .call_generate(&mut f.store,
            pk::KeygenParams::Ed(pk::EdwardsCurve::Ed25519))
        .await.unwrap().unwrap();
    let msg = b"original".to_vec();
    let sig = f.bindings.openssl_component_pkey().pkey()
        .call_sign_message(&mut f.store, key, None, &msg, None)
        .await.unwrap().unwrap();
    let ok = f.bindings.openssl_component_pkey().pkey()
        .call_verify_message(&mut f.store, key, None,
                             &b"tampered".to_vec(), &sig, None)
        .await.unwrap().unwrap();
    assert!(!ok);
}

#[tokio::test]
async fn x25519_derive_agrees() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();

    let a = pk.call_generate(&mut f.store,
        pk::KeygenParams::X(pk::MontgomeryCurve::X25519))
        .await.unwrap().unwrap();
    let b = pk.call_generate(&mut f.store,
        pk::KeygenParams::X(pk::MontgomeryCurve::X25519))
        .await.unwrap().unwrap();

    // Extract each public key via raw_public, re-import as public pkey,
    // derive both ways, check agreement.
    let a_pub = pk.call_raw_public(&mut f.store, a).await.unwrap().unwrap();
    let b_pub = pk.call_raw_public(&mut f.store, b).await.unwrap().unwrap();
    let a_pub_key = pk.call_from_raw_public(&mut f.store,
        pk::KeyType::X(pk::MontgomeryCurve::X25519), &a_pub)
        .await.unwrap().unwrap();
    let b_pub_key = pk.call_from_raw_public(&mut f.store,
        pk::KeyType::X(pk::MontgomeryCurve::X25519), &b_pub)
        .await.unwrap().unwrap();

    let ss1 = pk.call_derive(&mut f.store, a, b_pub_key)
        .await.unwrap().unwrap();
    let ss2 = pk.call_derive(&mut f.store, b, a_pub_key)
        .await.unwrap().unwrap();
    assert_eq!(ss1, ss2);
    assert_eq!(ss1.len(), 32);
}

#[tokio::test]
async fn rsa_2048_pkcs1_sign_verify() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let key = pk.call_generate(&mut f.store,
        pk::KeygenParams::Rsa(pk::RsaKeygen { bits: 2048, public_exponent: None }))
        .await.unwrap().unwrap();
    let msg = b"attest".to_vec();
    let sig = pk.call_sign_message(&mut f.store, key,
        Some(Algorithm::Sha256), &msg,
        Some(&pk::RsaPadding::Pkcs1))
        .await.unwrap().unwrap();
    let ok = pk.call_verify_message(&mut f.store, key,
        Some(Algorithm::Sha256), &msg, &sig,
        Some(&pk::RsaPadding::Pkcs1))
        .await.unwrap().unwrap();
    assert!(ok);
}

#[tokio::test]
async fn ec_p384_kind_reports_correct_curve() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let key = pk.call_generate(&mut f.store,
        pk::KeygenParams::Ec(pk::Curve::P384))
        .await.unwrap().unwrap();
    let kind = pk.call_kind(&mut f.store, key).await.unwrap();
    assert!(matches!(kind, pk::KeyType::Ec(pk::Curve::P384)));
}
