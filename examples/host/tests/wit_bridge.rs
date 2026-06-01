//! End-to-end smoke tests for the wit-bridge provider chain:
//!   - `sign-with-wit-bridge`     (Phase 3 gate): signs through the
//!     full openssl-wasm + simple-provider-adapter + stub-key-backend
//!     stack and verifies the signature with openssl-rs against the
//!     stub's baked SPKI.
//!   - `encode-spki-with-wit-bridge` (#296c gate): drives
//!     OSSL_ENCODER_to_data through the same stack and checks the
//!     returned SubjectPublicKeyInfo bytes match the baked SPKI.
//!
//! Set OPENSSL_WASM_COMPONENT to the composed wasm built by:
//!
//!   bash examples/host/tests/build_wit_bridge_stack.sh
//!   export OPENSSL_WASM_COMPONENT=/tmp/full-stack.wasm
//!
//! The compose recipe lives at
//! examples/host/tests/wit_bridge_stub_compose.wac. It wires
//! stub-key-backend as the Layer-3 backend and noop-provider for the
//! unused openssl:store/store import.

use openssl_wasm_host::{Fixture, exports};

use openssl::bn::BigNumContext;
use openssl::ec::{EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};

/// The SPKI DER baked into stub-key-backend's src/lib.rs. Update both
/// places if you ever regenerate the stub key. The test verifies that
/// signatures produced through the wit-bridge actually validate
/// against this public key.
const STUB_SPKI_DER: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0x64, 0x28, 0xbf, 0xda, 0x30, 0xa6, 0x5d, 0x9d, 0x76,
    0x2a, 0x91, 0x80, 0x2f, 0x2a, 0x7e, 0x4e, 0x8a, 0xc4, 0x1f, 0x78, 0x7a,
    0x8e, 0x2e, 0x86, 0x6b, 0x6d, 0xe7, 0xe4, 0x34, 0xff, 0xa6, 0xe1, 0x7f,
    0xc0, 0x94, 0xd5, 0x99, 0x96, 0xe1, 0xea, 0x43, 0x0a, 0xaa, 0x55, 0x54,
    0x04, 0x37, 0xb2, 0x3c, 0xe6, 0x62, 0xdc, 0xd4, 0x4e, 0x3b, 0xdc, 0x7f,
    0xb2, 0x2f, 0xbd, 0xcd, 0xb2, 0x50, 0xeb,
];

fn stub_public_key() -> PKey<Public> {
    PKey::public_key_from_der(STUB_SPKI_DER)
        .expect("stub SPKI DER should parse")
}

#[tokio::test]
async fn wit_bridge_sign_round_trip() {
    let mut fx = Fixture::new().await.expect("fixture");

    // The stub-key-backend ignores the URI; pass any string. The
    // adapter advertises ECDSA-with-SHA256, the stub only supports
    // SHA-256.
    let uri    = "stub://hardcoded".to_string();
    let mdname = "SHA2-256".to_string();
    let tbs    = b"phase-3 wit-bridge end-to-end check".to_vec();

    let result = fx.bindings
        .openssl_component_wit_bridge_test()
        .call_sign_with_wit_bridge(&mut fx.store, &uri, &mdname, &tbs)
        .await
        .expect("wasm call");

    let sig = match result {
        Ok(s)  => s,
        Err(e) => panic!("wit-bridge sign failed: {e}"),
    };
    assert!(!sig.is_empty(), "signature should be non-empty");

    // Verify the signature with openssl-rs against the stub's known
    // SPKI. ECDSA signatures from the stub are DER-encoded {r, s}.
    let pubkey = stub_public_key();
    let mut verifier = openssl::sign::Verifier::new(
        MessageDigest::sha256(), &pubkey)
        .expect("verifier");
    verifier.update(&tbs).expect("update");
    let ok = verifier.verify(&sig).expect("verify");
    assert!(ok, "signature did not verify under the stub's SPKI -- \
        the full Layer-1+2+3 chain produced an invalid signature, \
        or the SPKI is desynced from the stub's private key");
}

/// #296 follow-up: drive the full OSSL_ENCODER chain through the
/// wit-bridge and verify the returned SPKI bytes match the stub's
/// known public key. Exercises wit_encoder_encode + simple-provider-
/// adapter's encoder.encode wired to key.public-key-info.
#[tokio::test]
async fn wit_bridge_encode_spki_round_trip() {
    let mut fx = Fixture::new().await.expect("fixture");

    let uri = "stub://hardcoded".to_string();
    let result = fx.bindings
        .openssl_component_wit_bridge_test()
        .call_encode_spki_with_wit_bridge(&mut fx.store, &uri)
        .await
        .expect("wasm call");

    let spki = match result {
        Ok(s)  => s,
        Err(e) => panic!("wit-bridge encode-spki failed: {e}"),
    };
    assert_eq!(spki, STUB_SPKI_DER,
        "OSSL_ENCODER_to_data returned SPKI bytes that don't match the stub's baked key. \
         The encoder chain produced something, but it isn't the public key we expected — \
         either the C bridge dropped/corrupted bytes, or the adapter is reading the wrong key.");
    // Independent sanity: openssl-rs must accept what we got back.
    let _pubkey = PKey::public_key_from_der(&spki)
        .expect("encoded SPKI should parse as a public key");
}

/// Sanity: the stub's SPKI parses as a P-256 EC public key.
#[test]
fn stub_spki_is_p256() {
    let pkey = stub_public_key();
    let ec = pkey.ec_key().expect("EC key");
    let group = ec.group();
    let name = group.curve_name().expect("named curve");
    assert_eq!(name, Nid::X9_62_PRIME256V1);
    // Sanity: the encoded point round-trips.
    let _ctx = BigNumContext::new().unwrap();
    let pt: EcPoint = ec.public_key().to_owned(group).unwrap();
    let der = EcKey::from_public_key(group, &pt).unwrap()
        .public_key_to_der().unwrap();
    assert_eq!(der, STUB_SPKI_DER);
}
