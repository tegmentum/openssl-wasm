//! Extended x509 coverage: CSR, PKCS#12, CMS, intermediates.

use openssl_wasm_host::{Fixture, exports};
use exports::openssl::component::digest::Algorithm;
use exports::openssl::component::pkey as pk;
use exports::openssl::component::x509 as x;

async fn ed25519_key(f: &mut Fixture) -> wasmtime::component::ResourceAny {
    f.bindings.openssl_component_pkey().pkey()
        .call_generate(&mut f.store,
            pk::KeygenParams::Ed(pk::EdwardsCurve::Ed25519))
        .await.unwrap().unwrap()
}

async fn self_signed(
    f: &mut Fixture,
    cn: &str,
    is_ca: bool,
    eku: Vec<x::ExtendedKeyUsage>,
) -> (wasmtime::component::ResourceAny, wasmtime::component::ResourceAny) {
    let key = ed25519_key(f).await;
    let subj = vec![x::NameEntry { oid: "CN".into(), value: cn.into() }];
    let builder = x::CertificateBuilderInput {
        subject: subj.clone(),
        issuer: subj,
        serial_hex: Some("01".into()),
        validity: x::Validity {
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after:  "2099-01-01T00:00:00Z".into(),
        },
        subject_alt_names: vec![x::GeneralName::Dns(cn.into())],
        key_usage: if is_ca {
            Some(x::KeyUsage::KEY_CERT_SIGN | x::KeyUsage::CRL_SIGN)
        } else {
            Some(x::KeyUsage::DIGITAL_SIGNATURE)
        },
        extended_key_usage: eku,
        basic_constraints: Some(x::BasicConstraints { is_ca, path_len: None }),
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
async fn csr_build_encode_parse_verify() {
    let mut f = Fixture::new().await.unwrap();
    let key = ed25519_key(&mut f).await;
    let info = x::CsrInfo {
        subject: vec![x::NameEntry { oid: "CN".into(), value: "csr-test".into() }],
        subject_alt_names: vec![x::GeneralName::Dns("csr.example".into())],
    };
    let csr = f.bindings.openssl_component_x509().csr()
        .call_build_and_sign(&mut f.store, &info, key, Algorithm::Sha512)
        .await.unwrap().unwrap();

    let der = f.bindings.openssl_component_x509().csr()
        .call_encode(&mut f.store, csr, x::Encoding::Der)
        .await.unwrap().unwrap();
    let parsed = f.bindings.openssl_component_x509().csr()
        .call_parse(&mut f.store, &der, x::Encoding::Der)
        .await.unwrap().unwrap();

    let ok = f.bindings.openssl_component_x509().csr()
        .call_verify_signature(&mut f.store, parsed).await.unwrap().unwrap();
    assert!(ok);

    let parsed_info = f.bindings.openssl_component_x509().csr()
        .call_info(&mut f.store, parsed).await.unwrap();
    assert!(parsed_info.subject.iter().any(|e| e.oid == "CN" && e.value == "csr-test"));
}

#[tokio::test]
async fn pkcs12_build_parse_round_trip() {
    let mut f = Fixture::new().await.unwrap();
    let (cert, key) = self_signed(&mut f, "pkcs12-test", false,
        vec![x::ExtendedKeyUsage::ClientAuth]).await;

    let passphrase = b"strong passphrase".to_vec();
    let key_clone = f.bindings.openssl_component_pkey().pkey()
        .call_clone(&mut f.store, key).await.unwrap();
    let cert_clone = f.bindings.openssl_component_x509().certificate()
        .call_clone(&mut f.store, cert).await.unwrap();
    let bag = f.bindings.openssl_component_x509()
        .call_pkcs12_build(&mut f.store, &x::Pkcs12BuildInput {
            friendly_name: Some("friendly".into()),
            key: key_clone,
            cert: cert_clone,
            extra_certs: vec![],
            passphrase: passphrase.clone(),
        })
        .await.unwrap().unwrap();
    assert!(!bag.is_empty());

    let contents = f.bindings.openssl_component_x509()
        .call_pkcs12_parse(&mut f.store, &bag, &passphrase)
        .await.unwrap().unwrap();
    assert!(contents.key.is_some());
    assert!(contents.cert.is_some());
}

#[tokio::test]
async fn cms_sign_verify_round_trip() {
    // CMS requires a digest-then-sign algorithm; Ed25519 signers aren't
    // directly supported by CMS_sign. Use ECDSA P-256.
    let mut f = Fixture::new().await.unwrap();
    let key = f.bindings.openssl_component_pkey().pkey()
        .call_generate(&mut f.store, pk::KeygenParams::Ec(pk::Curve::P256))
        .await.unwrap().unwrap();
    let subj = vec![x::NameEntry { oid: "CN".into(), value: "cms-signer".into() }];
    let builder = x::CertificateBuilderInput {
        subject: subj.clone(),
        issuer: subj,
        serial_hex: Some("01".into()),
        validity: x::Validity {
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after:  "2099-01-01T00:00:00Z".into(),
        },
        subject_alt_names: vec![x::GeneralName::Email("a@example.com".into())],
        key_usage: Some(x::KeyUsage::DIGITAL_SIGNATURE),
        extended_key_usage: vec![x::ExtendedKeyUsage::EmailProtection],
        basic_constraints: None,
        subject_key: f.bindings.openssl_component_pkey().pkey()
            .call_clone(&mut f.store, key).await.unwrap(),
        signature_hash: Algorithm::Sha256,
    };
    let cert = f.bindings.openssl_component_x509()
        .call_build_and_sign(&mut f.store, &builder, key)
        .await.unwrap().unwrap();

    let content = b"message to sign with CMS".to_vec();
    let cms = f.bindings.openssl_component_x509()
        .call_cms_sign(&mut f.store, &content, key, cert, &vec![],
                       false /* attached */, x::Encoding::Der)
        .await.unwrap().unwrap();

    // Build store trusting the signer's self-signed cert.
    let store = f.bindings.openssl_component_x509().store()
        .call_constructor(&mut f.store).await.unwrap();
    f.bindings.openssl_component_x509().store()
        .call_add_trusted(&mut f.store, store, cert).await.unwrap().unwrap();

    let recovered = f.bindings.openssl_component_x509()
        .call_cms_verify(&mut f.store, &cms, store, None, x::Encoding::Der)
        .await.unwrap().unwrap();
    assert_eq!(recovered, Some(content));
}

#[tokio::test]
async fn chain_verify_with_intermediate() {
    // Build a 3-tier hierarchy: root CA → intermediate CA → leaf.
    let mut f = Fixture::new().await.unwrap();
    let (root, root_key) = self_signed(&mut f, "Root CA", true, vec![]).await;

    // Intermediate cert, issued by root.
    let interm_key = ed25519_key(&mut f).await;
    let interm_subj = vec![x::NameEntry { oid: "CN".into(), value: "Intermediate".into() }];
    let root_subj = vec![x::NameEntry { oid: "CN".into(), value: "Root CA".into() }];
    let interm_builder = x::CertificateBuilderInput {
        subject: interm_subj.clone(),
        issuer: root_subj.clone(),
        serial_hex: Some("10".into()),
        validity: x::Validity {
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after:  "2099-01-01T00:00:00Z".into(),
        },
        subject_alt_names: vec![],
        key_usage: Some(x::KeyUsage::KEY_CERT_SIGN | x::KeyUsage::CRL_SIGN),
        extended_key_usage: vec![],
        basic_constraints: Some(x::BasicConstraints { is_ca: true, path_len: Some(0) }),
        subject_key: f.bindings.openssl_component_pkey().pkey()
            .call_clone(&mut f.store, interm_key).await.unwrap(),
        signature_hash: Algorithm::Sha512,
    };
    let interm = f.bindings.openssl_component_x509()
        .call_build_and_sign(&mut f.store, &interm_builder, root_key)
        .await.unwrap().unwrap();

    // Leaf, issued by intermediate.
    let leaf_key = ed25519_key(&mut f).await;
    let leaf_subj = vec![x::NameEntry { oid: "CN".into(), value: "leaf.example".into() }];
    let leaf_builder = x::CertificateBuilderInput {
        subject: leaf_subj,
        issuer: interm_subj,
        serial_hex: Some("20".into()),
        validity: x::Validity {
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after:  "2099-01-01T00:00:00Z".into(),
        },
        subject_alt_names: vec![x::GeneralName::Dns("leaf.example".into())],
        key_usage: Some(x::KeyUsage::DIGITAL_SIGNATURE),
        extended_key_usage: vec![x::ExtendedKeyUsage::ServerAuth],
        basic_constraints: None,
        subject_key: leaf_key,
        signature_hash: Algorithm::Sha512,
    };
    let leaf = f.bindings.openssl_component_x509()
        .call_build_and_sign(&mut f.store, &leaf_builder, interm_key)
        .await.unwrap().unwrap();

    let store = f.bindings.openssl_component_x509().store()
        .call_constructor(&mut f.store).await.unwrap();
    f.bindings.openssl_component_x509().store()
        .call_add_trusted(&mut f.store, store, root).await.unwrap().unwrap();

    let opts = x::VerifyOptions {
        hostname: Some("leaf.example".into()),
        ip: None, purpose: None, at: None,
        partial_chain: false, crl_check: false, crl_check_all: false,
    };
    let chain = f.bindings.openssl_component_x509()
        .call_verify_chain(&mut f.store, store, leaf, &vec![interm], &opts)
        .await.unwrap().unwrap();
    assert_eq!(chain.len(), 3, "chain should be leaf → interm → root");
}

#[tokio::test]
async fn partial_chain_flag_accepts_intermediate_as_anchor() {
    // Same setup but anchor on the intermediate (not the root), with
    // partial_chain=true. The chain verifies without needing the root.
    let mut f = Fixture::new().await.unwrap();
    let (root, root_key) = self_signed(&mut f, "Root CA", true, vec![]).await;

    let interm_key = ed25519_key(&mut f).await;
    let interm_builder = x::CertificateBuilderInput {
        subject: vec![x::NameEntry { oid: "CN".into(), value: "Intermediate".into() }],
        issuer: vec![x::NameEntry { oid: "CN".into(), value: "Root CA".into() }],
        serial_hex: Some("10".into()),
        validity: x::Validity {
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after:  "2099-01-01T00:00:00Z".into(),
        },
        subject_alt_names: vec![],
        key_usage: Some(x::KeyUsage::KEY_CERT_SIGN),
        extended_key_usage: vec![],
        basic_constraints: Some(x::BasicConstraints { is_ca: true, path_len: None }),
        subject_key: f.bindings.openssl_component_pkey().pkey()
            .call_clone(&mut f.store, interm_key).await.unwrap(),
        signature_hash: Algorithm::Sha512,
    };
    let interm = f.bindings.openssl_component_x509()
        .call_build_and_sign(&mut f.store, &interm_builder, root_key)
        .await.unwrap().unwrap();
    let _ = root;

    // Leaf issued by intermediate.
    let leaf_key = ed25519_key(&mut f).await;
    let leaf_builder = x::CertificateBuilderInput {
        subject: vec![x::NameEntry { oid: "CN".into(), value: "leaf.example".into() }],
        issuer: vec![x::NameEntry { oid: "CN".into(), value: "Intermediate".into() }],
        serial_hex: Some("20".into()),
        validity: x::Validity {
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after:  "2099-01-01T00:00:00Z".into(),
        },
        subject_alt_names: vec![x::GeneralName::Dns("leaf.example".into())],
        key_usage: Some(x::KeyUsage::DIGITAL_SIGNATURE),
        extended_key_usage: vec![x::ExtendedKeyUsage::ServerAuth],
        basic_constraints: None,
        subject_key: leaf_key,
        signature_hash: Algorithm::Sha512,
    };
    let leaf = f.bindings.openssl_component_x509()
        .call_build_and_sign(&mut f.store, &leaf_builder, interm_key)
        .await.unwrap().unwrap();

    let store = f.bindings.openssl_component_x509().store()
        .call_constructor(&mut f.store).await.unwrap();
    f.bindings.openssl_component_x509().store()
        .call_add_trusted(&mut f.store, store, interm).await.unwrap().unwrap();

    let opts = x::VerifyOptions {
        hostname: Some("leaf.example".into()),
        ip: None, purpose: None, at: None,
        partial_chain: true,
        crl_check: false, crl_check_all: false,
    };
    let chain = f.bindings.openssl_component_x509()
        .call_verify_chain(&mut f.store, store, leaf, &vec![], &opts)
        .await.unwrap().unwrap();
    assert_eq!(chain.len(), 2, "partial chain should anchor on intermediate");
}

#[tokio::test]
async fn ip_san_matches_ip_verify_option() {
    let mut f = Fixture::new().await.unwrap();
    let key = ed25519_key(&mut f).await;
    let subj = vec![x::NameEntry { oid: "CN".into(), value: "192.0.2.1".into() }];
    let builder = x::CertificateBuilderInput {
        subject: subj.clone(),
        issuer: subj,
        serial_hex: Some("01".into()),
        validity: x::Validity {
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after:  "2099-01-01T00:00:00Z".into(),
        },
        subject_alt_names: vec![x::GeneralName::Ip(vec![192, 0, 2, 1])],
        key_usage: Some(x::KeyUsage::DIGITAL_SIGNATURE),
        extended_key_usage: vec![x::ExtendedKeyUsage::ServerAuth],
        basic_constraints: None,
        subject_key: f.bindings.openssl_component_pkey().pkey()
            .call_clone(&mut f.store, key).await.unwrap(),
        signature_hash: Algorithm::Sha512,
    };
    let cert = f.bindings.openssl_component_x509()
        .call_build_and_sign(&mut f.store, &builder, key)
        .await.unwrap().unwrap();

    let store = f.bindings.openssl_component_x509().store()
        .call_constructor(&mut f.store).await.unwrap();
    f.bindings.openssl_component_x509().store()
        .call_add_trusted(&mut f.store, store, cert).await.unwrap().unwrap();

    // Verify with ip=192.0.2.1.
    let opts_good = x::VerifyOptions {
        hostname: None,
        ip: Some("192.0.2.1".into()),
        purpose: None, at: None,
        partial_chain: false, crl_check: false, crl_check_all: false,
    };
    f.bindings.openssl_component_x509()
        .call_verify_chain(&mut f.store, store, cert, &vec![], &opts_good)
        .await.unwrap().unwrap();

    // Verify with wrong ip fails.
    let opts_bad = x::VerifyOptions {
        hostname: None,
        ip: Some("192.0.2.99".into()),
        purpose: None, at: None,
        partial_chain: false, crl_check: false, crl_check_all: false,
    };
    let r = f.bindings.openssl_component_x509()
        .call_verify_chain(&mut f.store, store, cert, &vec![], &opts_bad)
        .await.unwrap();
    assert!(r.is_err(), "wrong IP should fail");
}
