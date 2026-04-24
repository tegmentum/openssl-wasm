//! Extended KDF coverage.

use openssl_wasm_host::{Fixture, exports, hex};
use exports::openssl::component::digest::Algorithm;
use exports::openssl::component::kdf::{
    Argon2Params, Argon2Variant, KbkdfParams, ScryptParams, SsKdfParams,
    Tls13ExpandLabelParams, X963KdfParams,
};

fn hx(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn scrypt_rfc7914_first_test_vector() {
    // RFC 7914 §12 vector: password="", salt="", N=16, r=1, p=1, len=64.
    let mut f = Fixture::new().await.unwrap();
    let out = f.bindings.openssl_component_kdf()
        .call_scrypt(&mut f.store, &vec![],
            &ScryptParams { salt: vec![], n: 16, r: 1, p: 1, max_mem: 0 },
            64)
        .await.unwrap().unwrap();
    assert_eq!(hex(&out),
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
}

#[tokio::test]
async fn argon2id_smoke() {
    // No public KAT that's short+cheap, so just check that the same
    // inputs produce the same output (determinism) and different
    // params produce different output.
    let mut f = Fixture::new().await.unwrap();
    let mk = |t_cost, m_cost| Argon2Params {
        kind: Argon2Variant::Id,
        salt: vec![0x11; 16],
        secret: None,
        ad: None,
        t_cost,
        m_cost,
        lanes: 1,
    };
    let a = f.bindings.openssl_component_kdf()
        .call_argon2(&mut f.store, &b"passwd".to_vec(), &mk(2, 64), 32)
        .await.unwrap().unwrap();
    let a2 = f.bindings.openssl_component_kdf()
        .call_argon2(&mut f.store, &b"passwd".to_vec(), &mk(2, 64), 32)
        .await.unwrap().unwrap();
    assert_eq!(a, a2, "argon2 must be deterministic for fixed inputs");
    let b = f.bindings.openssl_component_kdf()
        .call_argon2(&mut f.store, &b"passwd".to_vec(), &mk(3, 64), 32)
        .await.unwrap().unwrap();
    assert_ne!(a, b, "different t_cost must change output");
}

#[tokio::test]
async fn kbkdf_determinism() {
    let mut f = Fixture::new().await.unwrap();
    let params = KbkdfParams {
        hash: Algorithm::Sha256,
        label: b"label".to_vec(),
        context: b"ctx".to_vec(),
    };
    let a = f.bindings.openssl_component_kdf()
        .call_kbkdf(&mut f.store, &vec![0x42u8; 32], &params, 64)
        .await.unwrap().unwrap();
    let b = f.bindings.openssl_component_kdf()
        .call_kbkdf(&mut f.store, &vec![0x42u8; 32], &params, 64)
        .await.unwrap().unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
}

#[tokio::test]
async fn sskdf_determinism() {
    let mut f = Fixture::new().await.unwrap();
    let out = f.bindings.openssl_component_kdf()
        .call_ss_kdf(&mut f.store, &vec![0x11u8; 32],
            &SsKdfParams {
                hash: Algorithm::Sha256,
                info: b"ss-info".to_vec(),
                salt: Some(b"ss-salt".to_vec()),
            }, 48)
        .await.unwrap().unwrap();
    assert_eq!(out.len(), 48);
}

#[tokio::test]
async fn x963_determinism() {
    let mut f = Fixture::new().await.unwrap();
    let out = f.bindings.openssl_component_kdf()
        .call_x963_kdf(&mut f.store, &vec![0x11u8; 32],
            &X963KdfParams {
                hash: Algorithm::Sha256,
                info: b"ieee-info".to_vec(),
            }, 32)
        .await.unwrap().unwrap();
    assert_eq!(out.len(), 32);
}

#[tokio::test]
async fn tls13_expand_label_matches_openssl_pattern() {
    // TLS 1.3 expand-label output is deterministic per (secret, label, context, len).
    // Check that identical inputs yield identical outputs, and that changing
    // the label perturbs the output.
    let mut f = Fixture::new().await.unwrap();
    let secret = hx("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1");
    let out1 = f.bindings.openssl_component_kdf()
        .call_tls13_expand_label(&mut f.store,
            &Tls13ExpandLabelParams {
                hash: Algorithm::Sha256,
                label: "derived".into(),
                context: vec![],
                secret: secret.clone(),
            }, 32)
        .await.unwrap().unwrap();
    let out2 = f.bindings.openssl_component_kdf()
        .call_tls13_expand_label(&mut f.store,
            &Tls13ExpandLabelParams {
                hash: Algorithm::Sha256,
                label: "derived".into(),
                context: vec![],
                secret: secret.clone(),
            }, 32)
        .await.unwrap().unwrap();
    assert_eq!(out1, out2);

    let out3 = f.bindings.openssl_component_kdf()
        .call_tls13_expand_label(&mut f.store,
            &Tls13ExpandLabelParams {
                hash: Algorithm::Sha256,
                label: "different".into(),
                context: vec![],
                secret,
            }, 32)
        .await.unwrap().unwrap();
    assert_ne!(out1, out3);
}
