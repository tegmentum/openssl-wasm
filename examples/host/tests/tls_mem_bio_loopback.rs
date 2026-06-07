//! In-process mem-BIO loopback: tls.mem-bio-client + tls.mem-bio-server
//! exchange ciphertext through their respective BIOs to complete a TLS
//! 1.3 handshake and round-trip application data — entirely in memory,
//! no socket required, no host TLS implementation involved.
//!
//! Validates that the new server-side mem-BIO resource pairs correctly
//! against the existing mem-bio-client so callers can drive an
//! end-to-end TLS exchange inside the component.

use openssl_wasm_host::{Fixture, exports};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime::component::ResourceAny;

use exports::openssl::component::digest::Algorithm;
use exports::openssl::component::pkey as pk;
use exports::openssl::component::tls;
use exports::openssl::component::x509 as x;

/// Generate an Ed25519 server cert + key inside the component. Ed25519
/// keeps key-generation cost trivial relative to RSA — important for a
/// loopback test that runs on every `cargo test`. Server-name
/// matching is sidestepped via verify=None on the client.
async fn build_server_cert(f: &mut Fixture) -> (ResourceAny, ResourceAny) {
    let key = f.bindings.openssl_component_pkey().pkey()
        .call_generate(&mut f.store,
            pk::KeygenParams::Ed(pk::EdwardsCurve::Ed25519))
        .await.unwrap().unwrap();
    let subject = vec![x::NameEntry {
        oid: "CN".into(), value: "loopback".into(),
    }];
    let builder = x::CertificateBuilderInput {
        subject: subject.clone(),
        issuer: subject,
        serial_hex: Some("01".into()),
        validity: x::Validity {
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after:  "2099-01-01T00:00:00Z".into(),
        },
        subject_alt_names: vec![
            x::GeneralName::Dns("loopback".into()),
        ],
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
    (cert, key)
}

/// Drive both endpoints' handshake state machines while pumping
/// ciphertext between them. Returns when both report handshake_done()
/// or the round budget is exhausted (which would indicate a stall).
async fn pump_handshake(
    f: &mut Fixture,
    client: ResourceAny,
    server: ResourceAny,
) {
    const MAX_ROUNDS: u32 = 32;
    for round in 0..MAX_ROUNDS {
        let client_done = f.bindings.openssl_component_tls().mem_bio_client()
            .call_handshake_done(&mut f.store, client).await.unwrap();
        let server_done = f.bindings.openssl_component_tls().mem_bio_server()
            .call_handshake_done(&mut f.store, server).await.unwrap();
        if client_done && server_done { return; }

        if !client_done {
            // ok | err(would-block); err(handshake-failed) bubbles up
            let _ = f.bindings.openssl_component_tls().mem_bio_client()
                .call_do_handshake(&mut f.store, client).await.unwrap();
        }
        if !server_done {
            let _ = f.bindings.openssl_component_tls().mem_bio_server()
                .call_do_handshake(&mut f.store, server).await.unwrap();
        }

        // client out → server in
        let c2s = f.bindings.openssl_component_tls().mem_bio_client()
            .call_bio_read(&mut f.store, client, 16 * 1024).await.unwrap();
        let c2s_len = c2s.len();
        if c2s_len > 0 {
            f.bindings.openssl_component_tls().mem_bio_server()
                .call_bio_write(&mut f.store, server, &c2s).await.unwrap();
        }
        // server out → client in
        let s2c = f.bindings.openssl_component_tls().mem_bio_server()
            .call_bio_read(&mut f.store, server, 16 * 1024).await.unwrap();
        let s2c_len = s2c.len();
        if s2c_len > 0 {
            f.bindings.openssl_component_tls().mem_bio_client()
                .call_bio_write(&mut f.store, client, &s2c).await.unwrap();
        }
        if c2s_len == 0 && s2c_len == 0 {
            panic!("handshake stalled at round {round}: neither side produced ciphertext");
        }
    }
    panic!("handshake did not converge in {MAX_ROUNDS} rounds");
}

/// Pump one application-data record from `from` to `to` and read the
/// decrypted plaintext on the receiving side. Returns the plaintext.
async fn round_trip_one_byte_client_to_server(
    f: &mut Fixture,
    client: ResourceAny,
    server: ResourceAny,
    byte: u8,
) -> Vec<u8> {
    let written = f.bindings.openssl_component_tls().mem_bio_client()
        .call_write(&mut f.store, client, &[byte]).await.unwrap().unwrap();
    assert_eq!(written, 1, "client.write should accept the single byte");

    let cipher = f.bindings.openssl_component_tls().mem_bio_client()
        .call_bio_read(&mut f.store, client, 16 * 1024).await.unwrap();
    assert!(!cipher.is_empty(),
        "client should have produced a TLS record after write");

    let injected = f.bindings.openssl_component_tls().mem_bio_server()
        .call_bio_write(&mut f.store, server, &cipher).await.unwrap();
    assert_eq!(injected as usize, cipher.len(),
        "server bio-write should accept all ciphertext bytes");

    f.bindings.openssl_component_tls().mem_bio_server()
        .call_read(&mut f.store, server, 8).await.unwrap().unwrap()
}

async fn round_trip_one_byte_server_to_client(
    f: &mut Fixture,
    client: ResourceAny,
    server: ResourceAny,
    byte: u8,
) -> Vec<u8> {
    let written = f.bindings.openssl_component_tls().mem_bio_server()
        .call_write(&mut f.store, server, &[byte]).await.unwrap().unwrap();
    assert_eq!(written, 1);

    let cipher = f.bindings.openssl_component_tls().mem_bio_server()
        .call_bio_read(&mut f.store, server, 16 * 1024).await.unwrap();
    assert!(!cipher.is_empty());

    let injected = f.bindings.openssl_component_tls().mem_bio_client()
        .call_bio_write(&mut f.store, client, &cipher).await.unwrap();
    assert_eq!(injected as usize, cipher.len());

    f.bindings.openssl_component_tls().mem_bio_client()
        .call_read(&mut f.store, client, 8).await.unwrap().unwrap()
}

#[tokio::test]
async fn mem_bio_loopback_handshake_and_application_data() {
    let mut f = Fixture::with_builder(WasiCtxBuilder::new()).await.unwrap();
    let (cert, key) = build_server_cert(&mut f).await;

    let server_cfg = tls::ServerConfig {
        protocols: tls::ProtocolRange {
            min: tls::Protocol::Tls12, max: tls::Protocol::Tls13,
        },
        verify: tls::VerifyMode::None,
        client_trust: None,
        cert_chain: vec![cert],
        key,
        sni_hosts: vec![],
        alpn: None, ciphers: None, groups: None,
        session_tickets: tls::SessionTicketPolicy::Disabled,
        keylog: false,
    };
    let server = f.bindings.openssl_component_tls().mem_bio_server()
        .call_new(&mut f.store, &server_cfg).await.unwrap().unwrap();

    let client_cfg = tls::ClientConfig {
        protocols: tls::ProtocolRange {
            min: tls::Protocol::Tls12, max: tls::Protocol::Tls13,
        },
        verify: tls::VerifyMode::None,
        trust: None,
        verify_options: None,
        server_name: Some("loopback".into()),
        client_cert: None, client_key: None,
        alpn: None, ciphers: None, groups: None,
        enable_early_data: false, resume_session: None, keylog: false,
    };
    let client = f.bindings.openssl_component_tls().mem_bio_client()
        .call_new(&mut f.store, &client_cfg).await.unwrap().unwrap();

    pump_handshake(&mut f, client, server).await;

    // Both endpoints should report FINISHED state and agree on protocol.
    assert!(f.bindings.openssl_component_tls().mem_bio_client()
        .call_handshake_done(&mut f.store, client).await.unwrap());
    assert!(f.bindings.openssl_component_tls().mem_bio_server()
        .call_handshake_done(&mut f.store, server).await.unwrap());

    let c_version = f.bindings.openssl_component_tls().mem_bio_client()
        .call_version(&mut f.store, client).await.unwrap();
    let s_version = f.bindings.openssl_component_tls().mem_bio_server()
        .call_version(&mut f.store, server).await.unwrap();
    assert_eq!(c_version, s_version,
        "client and server must agree on negotiated TLS version");
    assert!(c_version.starts_with("TLSv1."),
        "negotiated version should be TLS 1.x, got: {c_version}");

    // 1 byte client → server
    let plain_at_server = round_trip_one_byte_client_to_server(
        &mut f, client, server, 0x58 /* 'X' */).await;
    assert_eq!(plain_at_server, b"X",
        "server should decrypt to 'X', got {plain_at_server:?}");

    // 1 byte server → client
    let plain_at_client = round_trip_one_byte_server_to_client(
        &mut f, client, server, 0x59 /* 'Y' */).await;
    assert_eq!(plain_at_client, b"Y",
        "client should decrypt to 'Y', got {plain_at_client:?}");

    // Tidy up.
    f.bindings.openssl_component_tls().mem_bio_client()
        .call_close(&mut f.store, client).await.unwrap();
    f.bindings.openssl_component_tls().mem_bio_server()
        .call_close(&mut f.store, server).await.unwrap();
}
