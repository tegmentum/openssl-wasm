//! Certificate build→parse→verify round-trip.

use openssl_wasm_host::{Fixture, exports};
use exports::openssl::component::digest::Algorithm;
use exports::openssl::component::pkey as pk;
use exports::openssl::component::x509 as x;

async fn build_self_signed(f: &mut Fixture) -> (
    wasmtime::component::ResourceAny,
    wasmtime::component::ResourceAny,
) {
    let key = f.bindings.openssl_component_pkey().pkey()
        .call_generate(&mut f.store,
            pk::KeygenParams::Ed(pk::EdwardsCurve::Ed25519))
        .await.unwrap().unwrap();
    let subject = vec![
        x::NameEntry { oid: "CN".into(), value: "openssl-wasm test CA".into() },
    ];
    let builder = x::CertificateBuilderInput {
        subject: subject.clone(),
        issuer: subject,
        serial_hex: Some("01".into()),
        validity: x::Validity {
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after:  "2027-01-01T00:00:00Z".into(),
        },
        subject_alt_names: vec![x::GeneralName::Dns("example.test".into())],
        key_usage: Some(x::KeyUsage::KEY_CERT_SIGN | x::KeyUsage::DIGITAL_SIGNATURE),
        extended_key_usage: vec![],
        basic_constraints: Some(x::BasicConstraints { is_ca: true, path_len: None }),
        subject_key: f.bindings.openssl_component_pkey().pkey()
            .call_clone(&mut f.store, key).await.unwrap(),
        signature_hash: Algorithm::Sha512,
    };
    let cert = f.bindings.openssl_component_x509()
        .call_build_and_sign(&mut f.store, &builder, key)
        .await.unwrap().unwrap();
    (cert, key)
}

#[tokio::test]
async fn build_encode_parse_verify_roundtrip() {
    let mut f = Fixture::new().await.unwrap();
    let (cert, _key) = build_self_signed(&mut f).await;

    let der = f.bindings.openssl_component_x509().certificate()
        .call_encode(&mut f.store, cert, x::Encoding::Der)
        .await.unwrap().unwrap();
    assert!(der.len() > 100);

    let parsed = f.bindings.openssl_component_x509().certificate()
        .call_parse(&mut f.store, &der, x::Encoding::Der)
        .await.unwrap().unwrap();

    let info = f.bindings.openssl_component_x509().certificate()
        .call_info(&mut f.store, parsed).await.unwrap();
    assert!(info.subject.iter().any(|e| e.oid == "CN" && e.value.contains("CA")));
    assert_eq!(info.signature_algorithm, "ED25519");
    assert!(!info.fingerprint_sha256.is_empty());
    assert_eq!(info.subject_alt_names.len(), 1);

    let pub_key = f.bindings.openssl_component_x509().certificate()
        .call_public_key(&mut f.store, parsed).await.unwrap();
    let ok = f.bindings.openssl_component_x509().certificate()
        .call_verify_signature(&mut f.store, parsed, pub_key)
        .await.unwrap().unwrap();
    assert!(ok);
}

#[tokio::test]
async fn chain_verify_against_trust_store() {
    let mut f = Fixture::new().await.unwrap();
    let (cert, _key) = build_self_signed(&mut f).await;

    let store = f.bindings.openssl_component_x509().store()
        .call_constructor(&mut f.store).await.unwrap();
    f.bindings.openssl_component_x509().store()
        .call_add_trusted(&mut f.store, store, cert).await.unwrap().unwrap();

    let opts = x::VerifyOptions {
        hostname: Some("example.test".into()),
        ip: None,
        purpose: None,
        at: None,
        partial_chain: false,
        crl_check: false,
        crl_check_all: false,
    };
    let chain = f.bindings.openssl_component_x509()
        .call_verify_chain(&mut f.store, store, cert, &vec![], &opts)
        .await.unwrap().unwrap();
    assert_eq!(chain.len(), 1);
}

#[tokio::test]
async fn chain_verify_rejects_hostname_mismatch() {
    let mut f = Fixture::new().await.unwrap();
    let (cert, _key) = build_self_signed(&mut f).await;
    let store = f.bindings.openssl_component_x509().store()
        .call_constructor(&mut f.store).await.unwrap();
    f.bindings.openssl_component_x509().store()
        .call_add_trusted(&mut f.store, store, cert).await.unwrap().unwrap();

    let opts = x::VerifyOptions {
        hostname: Some("not-in-san.example".into()),
        ip: None, purpose: None, at: None,
        partial_chain: false, crl_check: false, crl_check_all: false,
    };
    let res = f.bindings.openssl_component_x509()
        .call_verify_chain(&mut f.store, store, cert, &vec![], &opts)
        .await.unwrap();
    assert!(matches!(res, Err(x::X509Error::HostnameMismatch)));
}
