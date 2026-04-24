//! Robustness smoke tests: feed random/malformed byte strings to parse
//! paths and assert the component doesn't trap. These are not a
//! substitute for a real fuzz campaign; they're a CI-friendly spot
//! check that `make test` can run in seconds.

use std::sync::OnceLock;

use openssl_wasm_host::{Fixture, exports};
use exports::openssl::component::x509 as x;
use exports::openssl::component::pkey as pk;

fn deterministic_bytes(seed: u64, n: usize) -> Vec<u8> {
    // Tiny xorshift64 PRNG — we want repeatable corpora without pulling
    // in a random-number dep.
    let mut s = seed.max(1);
    (0..n).map(|_| {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        (s & 0xff) as u8
    }).collect()
}

#[tokio::test]
async fn certificate_parse_random_inputs() {
    let mut f = Fixture::new().await.unwrap();
    for i in 0..200u64 {
        for len in [4usize, 32, 256, 1024, 4096] {
            let input = deterministic_bytes(i, len);
            let r_der = f.bindings.openssl_component_x509().certificate()
                .call_parse(&mut f.store, &input, x::Encoding::Der)
                .await.unwrap();
            let r_pem = f.bindings.openssl_component_x509().certificate()
                .call_parse(&mut f.store, &input, x::Encoding::Pem)
                .await.unwrap();
            // Either both fail (expected) or one succeeds (extremely
            // unlikely but valid). The point is the component didn't trap.
            assert!(r_der.is_err() || r_der.is_ok());
            assert!(r_pem.is_err() || r_pem.is_ok());
        }
    }
    // Drain accumulated errors so later tests start clean.
    f.bindings.openssl_component_error()
        .call_clear_errors(&mut f.store).await.unwrap();
}

#[tokio::test]
async fn csr_parse_random_inputs() {
    let mut f = Fixture::new().await.unwrap();
    for i in 400..500u64 {
        let input = deterministic_bytes(i, 256);
        let _ = f.bindings.openssl_component_x509().csr()
            .call_parse(&mut f.store, &input, x::Encoding::Der)
            .await.unwrap();
    }
    f.bindings.openssl_component_error()
        .call_clear_errors(&mut f.store).await.unwrap();
}

#[tokio::test]
async fn crl_parse_random_inputs() {
    let mut f = Fixture::new().await.unwrap();
    for i in 600..700u64 {
        let input = deterministic_bytes(i, 256);
        let _ = f.bindings.openssl_component_x509().crl()
            .call_parse(&mut f.store, &input, x::Encoding::Der)
            .await.unwrap();
    }
    f.bindings.openssl_component_error()
        .call_clear_errors(&mut f.store).await.unwrap();
}

#[tokio::test]
async fn pkey_load_private_random_inputs() {
    let mut f = Fixture::new().await.unwrap();
    for i in 800..900u64 {
        let input = deterministic_bytes(i, 256);
        let _ = f.bindings.openssl_component_pkey().pkey()
            .call_load_private(&mut f.store, &input,
                &pk::LoadOptions {
                    format: pk::KeyFormat::Pkcs8,
                    encoding: pk::Encoding::Der,
                    passphrase: None,
                }).await.unwrap();
    }
    f.bindings.openssl_component_error()
        .call_clear_errors(&mut f.store).await.unwrap();
}

#[tokio::test]
async fn truncated_valid_cert_still_safe() {
    // Generate a valid self-signed cert, then feed progressively
    // more-truncated versions to the parser. Must never trap.
    let mut f = Fixture::new().await.unwrap();
    let key = f.bindings.openssl_component_pkey().pkey()
        .call_generate(&mut f.store,
            pk::KeygenParams::Ed(pk::EdwardsCurve::Ed25519))
        .await.unwrap().unwrap();
    let subj = vec![x::NameEntry { oid: "CN".into(), value: "test".into() }];
    let subject_key = f.bindings.openssl_component_pkey().pkey()
        .call_clone(&mut f.store, key).await.unwrap();
    let cert = f.bindings.openssl_component_x509()
        .call_build_and_sign(&mut f.store, &x::CertificateBuilderInput {
            subject: subj.clone(),
            issuer: subj,
            serial_hex: Some("01".into()),
            validity: x::Validity {
                not_before: "2026-01-01T00:00:00Z".into(),
                not_after:  "2099-01-01T00:00:00Z".into(),
            },
            subject_alt_names: vec![],
            key_usage: Some(x::KeyUsage::DIGITAL_SIGNATURE),
            extended_key_usage: vec![],
            basic_constraints: None,
            subject_key,
            signature_hash: exports::openssl::component::digest::Algorithm::Sha512,
        }, key).await.unwrap().unwrap();
    let der = f.bindings.openssl_component_x509().certificate()
        .call_encode(&mut f.store, cert, x::Encoding::Der)
        .await.unwrap().unwrap();

    // Step by 17 so we hit many random truncation points without
    // running for ages.
    for cut in (0..der.len()).step_by(17) {
        let slice = &der[..cut];
        let _ = f.bindings.openssl_component_x509().certificate()
            .call_parse(&mut f.store, &slice.to_vec(), x::Encoding::Der)
            .await.unwrap();
    }
    f.bindings.openssl_component_error()
        .call_clear_errors(&mut f.store).await.unwrap();
}

/// Fuzz-style corpus: a few known "tricky" inputs from the DER wild
/// (length bombs, deep nesting, huge integer signals) to catch trivial
/// regressions. Real campaigns belong in a dedicated cargo-fuzz crate.
#[tokio::test]
async fn tricky_der_shapes() {
    let mut f = Fixture::new().await.unwrap();
    let cases: &[&[u8]] = &[
        // Empty.
        &[],
        // Minimal but invalid DER.
        &[0x30, 0x00],
        // Length-claims-more-than-input.
        &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
        // Indefinite length form (BER, not DER).
        &[0x30, 0x80, 0x00, 0x00],
        // 8 MB of zeros.
        &vec![0u8; 8 * 1024 * 1024][..],
        // Deep nesting: 100 × SEQUENCE opens.
        &{
            let mut v = Vec::with_capacity(400);
            for _ in 0..100 { v.extend_from_slice(&[0x30, 0x82, 0x01, 0x00]); }
            v
        }[..],
    ];
    for (i, c) in cases.iter().enumerate() {
        let r = f.bindings.openssl_component_x509().certificate()
            .call_parse(&mut f.store, &c.to_vec(), x::Encoding::Der)
            .await.unwrap();
        assert!(r.is_err(), "tricky case {i} unexpectedly parsed OK");
    }
    f.bindings.openssl_component_error()
        .call_clear_errors(&mut f.store).await.unwrap();
}

// Silence unused import warning if added.
static _W: OnceLock<()> = OnceLock::new();
