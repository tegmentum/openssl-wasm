//! Extended pkey coverage: RSA-OAEP/PSS, ECDSA, Ed448, X448, DH, PEM/DER round-trips.

use openssl_wasm_host::{Fixture, exports};
use exports::openssl::component::digest::Algorithm;
use exports::openssl::component::pkey as pk;

#[tokio::test]
async fn rsa_oaep_sha256_encrypt_decrypt_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let key = pk.call_generate(&mut f.store,
        pk::KeygenParams::Rsa(pk::RsaKeygen { bits: 2048, public_exponent: None }))
        .await.unwrap().unwrap();
    let padding = pk::RsaPadding::Pkcs1Oaep(pk::OaepParams {
        hash: Algorithm::Sha256,
        mgf1_hash: Algorithm::Sha256,
        label: vec![],
    });
    let pt = b"oaep message".to_vec();
    let ct = pk.call_encrypt(&mut f.store, key, &padding, &pt)
        .await.unwrap().unwrap();
    let got = pk.call_decrypt(&mut f.store, key, &padding, &ct)
        .await.unwrap().unwrap();
    assert_eq!(got, pt);
}

#[tokio::test]
async fn rsa_pss_sign_verify() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let key = pk.call_generate(&mut f.store,
        pk::KeygenParams::Rsa(pk::RsaKeygen { bits: 2048, public_exponent: None }))
        .await.unwrap().unwrap();
    let padding = pk::RsaPadding::Pkcs1Pss(pk::PssParams {
        hash: Algorithm::Sha256,
        mgf1_hash: Algorithm::Sha256,
        salt_len: -1,  // RSA_PSS_SALTLEN_DIGEST
    });
    let msg = b"pss message".to_vec();
    let sig = pk.call_sign_message(&mut f.store, key,
        Some(Algorithm::Sha256), &msg, Some(&padding))
        .await.unwrap().unwrap();
    let ok = pk.call_verify_message(&mut f.store, key,
        Some(Algorithm::Sha256), &msg, &sig, Some(&padding))
        .await.unwrap().unwrap();
    assert!(ok);
}

#[tokio::test]
async fn ecdsa_p256_sha256_sign_verify() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let key = pk.call_generate(&mut f.store,
        pk::KeygenParams::Ec(pk::Curve::P256))
        .await.unwrap().unwrap();
    let msg = b"ecdsa message".to_vec();
    let sig = pk.call_sign_message(&mut f.store, key,
        Some(Algorithm::Sha256), &msg, None)
        .await.unwrap().unwrap();
    let ok = pk.call_verify_message(&mut f.store, key,
        Some(Algorithm::Sha256), &msg, &sig, None)
        .await.unwrap().unwrap();
    assert!(ok);
}

#[tokio::test]
async fn ecdsa_p384_sha384_sign_verify() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let key = pk.call_generate(&mut f.store,
        pk::KeygenParams::Ec(pk::Curve::P384))
        .await.unwrap().unwrap();
    let msg = b"p384 message".to_vec();
    let sig = pk.call_sign_message(&mut f.store, key,
        Some(Algorithm::Sha384), &msg, None)
        .await.unwrap().unwrap();
    let ok = pk.call_verify_message(&mut f.store, key,
        Some(Algorithm::Sha384), &msg, &sig, None)
        .await.unwrap().unwrap();
    assert!(ok);
}

#[tokio::test]
async fn ed448_sign_verify() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let key = pk.call_generate(&mut f.store,
        pk::KeygenParams::Ed(pk::EdwardsCurve::Ed448))
        .await.unwrap().unwrap();
    let msg = b"ed448 message".to_vec();
    let sig = pk.call_sign_message(&mut f.store, key, None, &msg, None)
        .await.unwrap().unwrap();
    let ok = pk.call_verify_message(&mut f.store, key, None, &msg, &sig, None)
        .await.unwrap().unwrap();
    assert!(ok);
    assert_eq!(sig.len(), 114);  // ed448 sig is 114 bytes
}

#[tokio::test]
async fn x448_derive_agreement() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let a = pk.call_generate(&mut f.store,
        pk::KeygenParams::X(pk::MontgomeryCurve::X448))
        .await.unwrap().unwrap();
    let b = pk.call_generate(&mut f.store,
        pk::KeygenParams::X(pk::MontgomeryCurve::X448))
        .await.unwrap().unwrap();
    let a_pub = pk.call_raw_public(&mut f.store, a).await.unwrap().unwrap();
    let b_pub = pk.call_raw_public(&mut f.store, b).await.unwrap().unwrap();
    let a_pub_key = pk.call_from_raw_public(&mut f.store,
        pk::KeyType::X(pk::MontgomeryCurve::X448), &a_pub)
        .await.unwrap().unwrap();
    let b_pub_key = pk.call_from_raw_public(&mut f.store,
        pk::KeyType::X(pk::MontgomeryCurve::X448), &b_pub)
        .await.unwrap().unwrap();
    let ss1 = pk.call_derive(&mut f.store, a, b_pub_key)
        .await.unwrap().unwrap();
    let ss2 = pk.call_derive(&mut f.store, b, a_pub_key)
        .await.unwrap().unwrap();
    assert_eq!(ss1, ss2);
    assert_eq!(ss1.len(), 56);  // X448 shared secret is 56 bytes
}

#[tokio::test]
async fn rsa_pkcs8_pem_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let key = pk.call_generate(&mut f.store,
        pk::KeygenParams::Rsa(pk::RsaKeygen { bits: 2048, public_exponent: None }))
        .await.unwrap().unwrap();
    let pem = pk.call_save_private(&mut f.store, key,
        &pk::SaveOptions {
            format: pk::KeyFormat::Pkcs8,
            encoding: pk::Encoding::Pem,
            passphrase: None,
        })
        .await.unwrap().unwrap();
    assert!(pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));

    let parsed = pk.call_load_private(&mut f.store, &pem,
        &pk::LoadOptions {
            format: pk::KeyFormat::Pkcs8,
            encoding: pk::Encoding::Pem,
            passphrase: None,
        })
        .await.unwrap().unwrap();
    assert_eq!(pk.call_bits(&mut f.store, parsed).await.unwrap(),
               pk.call_bits(&mut f.store, key).await.unwrap());

    // Signing with either should produce verifiable signatures against the other's pubkey.
    let msg = b"cross-instance message".to_vec();
    let sig = pk.call_sign_message(&mut f.store, parsed,
        Some(Algorithm::Sha256), &msg, Some(&pk::RsaPadding::Pkcs1))
        .await.unwrap().unwrap();
    let ok = pk.call_verify_message(&mut f.store, key,
        Some(Algorithm::Sha256), &msg, &sig, Some(&pk::RsaPadding::Pkcs1))
        .await.unwrap().unwrap();
    assert!(ok);
}

#[tokio::test]
async fn ec_spki_der_public_key_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let key = pk.call_generate(&mut f.store,
        pk::KeygenParams::Ec(pk::Curve::P256))
        .await.unwrap().unwrap();
    let der = pk.call_save_public(&mut f.store, key,
        &pk::SaveOptions {
            format: pk::KeyFormat::Spki,
            encoding: pk::Encoding::Der,
            passphrase: None,
        })
        .await.unwrap().unwrap();

    let parsed = pk.call_load_public(&mut f.store, &der,
        &pk::LoadOptions {
            format: pk::KeyFormat::Spki,
            encoding: pk::Encoding::Der,
            passphrase: None,
        })
        .await.unwrap().unwrap();
    let msg = b"signed by private, verified by parsed public".to_vec();
    let sig = pk.call_sign_message(&mut f.store, key,
        Some(Algorithm::Sha256), &msg, None)
        .await.unwrap().unwrap();
    let ok = pk.call_verify_message(&mut f.store, parsed,
        Some(Algorithm::Sha256), &msg, &sig, None)
        .await.unwrap().unwrap();
    assert!(ok);
}

#[tokio::test]
async fn has_private_differs_between_public_and_private() {
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let key = pk.call_generate(&mut f.store,
        pk::KeygenParams::Ec(pk::Curve::P256))
        .await.unwrap().unwrap();
    assert!(pk.call_has_private(&mut f.store, key).await.unwrap());

    let spki = pk.call_save_public(&mut f.store, key,
        &pk::SaveOptions {
            format: pk::KeyFormat::Spki,
            encoding: pk::Encoding::Der,
            passphrase: None,
        })
        .await.unwrap().unwrap();
    let pub_only = pk.call_load_public(&mut f.store, &spki,
        &pk::LoadOptions {
            format: pk::KeyFormat::Spki,
            encoding: pk::Encoding::Der,
            passphrase: None,
        })
        .await.unwrap().unwrap();
    assert!(!pk.call_has_private(&mut f.store, pub_only).await.unwrap());
}

#[tokio::test]
async fn dh_named_ffdhe2048_agreement() {
    // Two keypairs in the same RFC 7919 group share p,g — derive on
    // either side produces the same shared secret. This is the
    // real-world DH usage (TLS FFDHE), and it's fast because there's
    // no prime search.
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let a = pk.call_generate(&mut f.store,
        pk::KeygenParams::DhNamed(pk::DhGroup::Ffdhe2048))
        .await.unwrap().unwrap();
    let b = pk.call_generate(&mut f.store,
        pk::KeygenParams::DhNamed(pk::DhGroup::Ffdhe2048))
        .await.unwrap().unwrap();
    let ss1 = pk.call_derive(&mut f.store, a, b).await.unwrap().unwrap();
    let ss2 = pk.call_derive(&mut f.store, b, a).await.unwrap().unwrap();
    assert_eq!(ss1, ss2);
    assert_eq!(ss1.len(), 256);  // 2048-bit field element
    assert!(pk.call_bits(&mut f.store, a).await.unwrap() >= 2048);
}

#[tokio::test]
async fn dh_named_modp3072_agreement() {
    // RFC 3526 MODP-3072 — the IPsec flavor. Validates the modp_*
    // name-resolution path alongside the RFC 7919 ffdhe_* path.
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let a = pk.call_generate(&mut f.store,
        pk::KeygenParams::DhNamed(pk::DhGroup::Modp3072))
        .await.unwrap().unwrap();
    let b = pk.call_generate(&mut f.store,
        pk::KeygenParams::DhNamed(pk::DhGroup::Modp3072))
        .await.unwrap().unwrap();
    let ss = pk.call_derive(&mut f.store, a, b).await.unwrap().unwrap();
    assert_eq!(ss.len(), 384);  // 3072-bit field element
}

#[tokio::test]
#[ignore = "DH 2048-bit fresh prime generation is slow (>2 min on wasm); run with `cargo test -- --ignored`"]
async fn dh_fresh_param_generation() {
    // Opt-in regression check for the `dh(dh-keygen)` path that
    // generates a fresh safe prime. Real deployments should use
    // `dh-named` instead — this just keeps the slow path wired.
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let k = pk.call_generate(&mut f.store,
        pk::KeygenParams::Dh(pk::DhKeygen { prime_bits: 2048, generator: 2 }))
        .await.unwrap().unwrap();
    assert!(pk.call_bits(&mut f.store, k).await.unwrap() >= 2048);
}

#[tokio::test]
async fn ed25519_raw_public_matches_derived() {
    // Generate an Ed25519 key, export raw public, import raw public on a
    // fresh handle, verify signatures cross-handle.
    let mut f = Fixture::new().await.unwrap();
    let pk = f.bindings.openssl_component_pkey().pkey();
    let key = pk.call_generate(&mut f.store,
        pk::KeygenParams::Ed(pk::EdwardsCurve::Ed25519))
        .await.unwrap().unwrap();
    let raw = pk.call_raw_public(&mut f.store, key).await.unwrap().unwrap();
    assert_eq!(raw.len(), 32);
    let imported = pk.call_from_raw_public(&mut f.store,
        pk::KeyType::Ed(pk::EdwardsCurve::Ed25519), &raw)
        .await.unwrap().unwrap();
    let msg = b"raw public import".to_vec();
    let sig = pk.call_sign_message(&mut f.store, key, None, &msg, None)
        .await.unwrap().unwrap();
    let ok = pk.call_verify_message(&mut f.store, imported, None, &msg, &sig, None)
        .await.unwrap().unwrap();
    assert!(ok);
}
