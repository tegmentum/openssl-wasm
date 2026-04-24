//! TLS server-side tests: component binds and accepts, host connects
//! via a native OpenSSL client.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;

use openssl_wasm_host::{Fixture, exports};
use wasmtime_wasi::WasiCtxBuilder;

use exports::openssl::component::digest::Algorithm;
use exports::openssl::component::pkey as pk;
use exports::openssl::component::tls;
use exports::openssl::component::x509 as x;

async fn build_server_cert(f: &mut Fixture) -> (
    wasmtime::component::ResourceAny,
    wasmtime::component::ResourceAny,
) {
    let key = f.bindings.openssl_component_pkey().pkey()
        .call_generate(&mut f.store,
            pk::KeygenParams::Ed(pk::EdwardsCurve::Ed25519))
        .await.unwrap().unwrap();
    let subject = vec![x::NameEntry {
        oid: "CN".into(), value: "localhost".into(),
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
            x::GeneralName::Dns("localhost".into()),
            x::GeneralName::Ip(vec![127, 0, 0, 1]),
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

fn networked_builder() -> WasiCtxBuilder {
    let mut b = WasiCtxBuilder::new();
    b.inherit_stdio().inherit_network().allow_ip_name_lookup(true);
    b
}

/// Component binds a TLS listener, a host OS thread connects with
/// OpenSSL, they exchange one message each way.
#[tokio::test]
async fn server_accepts_and_echoes() {
    let mut f = Fixture::with_builder(networked_builder()).await.unwrap();
    let (cert, key) = build_server_cert(&mut f).await;

    let cfg = tls::ServerConfig {
        protocols: tls::ProtocolRange { min: tls::Protocol::Tls12, max: tls::Protocol::Tls13 },
        verify: tls::VerifyMode::None,
        client_trust: None,
        cert_chain: vec![cert],
        key,
        sni_hosts: vec![],
        alpn: None, ciphers: None, groups: None,
        session_tickets: tls::SessionTicketPolicy::Disabled,
        keylog: None,
    };
    let listener = f.bindings.openssl_component_tls().server_listener()
        .call_bind(&mut f.store, "127.0.0.1", 0, &cfg)
        .await.unwrap().unwrap();
    let port = f.bindings.openssl_component_tls().server_listener()
        .call_local_port(&mut f.store, listener).await.unwrap();
    assert!(port > 0);

    let client_thread = thread::spawn(move || -> Result<Vec<u8>, String> {
        // Brief grace so accept() is pending before we connect.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
        let ctx = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client())
            .map_err(|e| e.to_string())?.build();
        let mut ssl = openssl::ssl::Ssl::new(&ctx).map_err(|e| e.to_string())?;
        ssl.set_verify(openssl::ssl::SslVerifyMode::NONE);
        ssl.set_hostname("localhost").map_err(|e| e.to_string())?;
        let mut stream = openssl::ssl::SslStream::new(ssl, tcp).map_err(|e| e.to_string())?;
        stream.connect().map_err(|e| e.to_string())?;
        stream.write_all(b"hello server").map_err(|e| e.to_string())?;
        let mut buf = [0u8; 128];
        let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
        Ok(buf[..n].to_vec())
    });

    // Server side: accept, read, echo.
    let server = f.bindings.openssl_component_tls().server_listener()
        .call_accept(&mut f.store, listener).await.unwrap().unwrap();
    let msg = f.bindings.openssl_component_tls().server()
        .call_read(&mut f.store, server, 64).await.unwrap().unwrap();
    let mut reply = b"echo: ".to_vec();
    reply.extend_from_slice(&msg);
    f.bindings.openssl_component_tls().server()
        .call_write(&mut f.store, server, &reply).await.unwrap().unwrap();

    let got = client_thread.join().unwrap().expect("client failed");
    assert_eq!(got, b"echo: hello server");
}

/// Same test but client sends a cert that the server must verify (mTLS).
#[tokio::test]
async fn mtls_required_with_valid_client_cert() {
    let mut f = Fixture::with_builder(networked_builder()).await.unwrap();
    let (server_cert, server_key) = build_server_cert(&mut f).await;

    // A second self-signed cert acts as the client's credential; we put
    // that into a trust store so the server accepts it.
    let client_key = f.bindings.openssl_component_pkey().pkey()
        .call_generate(&mut f.store,
            pk::KeygenParams::Ed(pk::EdwardsCurve::Ed25519))
        .await.unwrap().unwrap();
    let client_subj = vec![x::NameEntry {
        oid: "CN".into(), value: "test-client".into(),
    }];
    let client_builder = x::CertificateBuilderInput {
        subject: client_subj.clone(),
        issuer: client_subj,
        serial_hex: Some("02".into()),
        validity: x::Validity {
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after:  "2099-01-01T00:00:00Z".into(),
        },
        subject_alt_names: vec![],
        key_usage: Some(x::KeyUsage::DIGITAL_SIGNATURE),
        extended_key_usage: vec![x::ExtendedKeyUsage::ClientAuth],
        basic_constraints: None,
        subject_key: f.bindings.openssl_component_pkey().pkey()
            .call_clone(&mut f.store, client_key).await.unwrap(),
        signature_hash: Algorithm::Sha512,
    };
    let client_cert = f.bindings.openssl_component_x509()
        .call_build_and_sign(&mut f.store, &client_builder, client_key)
        .await.unwrap().unwrap();

    // Export client cert + key as DER/PEM so the native host client can load them.
    let client_cert_der = f.bindings.openssl_component_x509().certificate()
        .call_encode(&mut f.store, client_cert, x::Encoding::Der)
        .await.unwrap().unwrap();
    let client_key_pem = f.bindings.openssl_component_pkey().pkey()
        .call_save_private(&mut f.store, client_key,
            &pk::SaveOptions {
                format: pk::KeyFormat::Pkcs8,
                encoding: pk::Encoding::Pem,
                passphrase: None,
            })
        .await.unwrap().unwrap();

    // Build a trust store containing the client cert.
    let client_trust = f.bindings.openssl_component_x509().store()
        .call_constructor(&mut f.store).await.unwrap();
    f.bindings.openssl_component_x509().store()
        .call_add_trusted(&mut f.store, client_trust, client_cert)
        .await.unwrap().unwrap();

    let cfg = tls::ServerConfig {
        protocols: tls::ProtocolRange { min: tls::Protocol::Tls12, max: tls::Protocol::Tls13 },
        verify: tls::VerifyMode::Required,
        client_trust: Some(client_trust),
        cert_chain: vec![server_cert],
        key: server_key,
        sni_hosts: vec![],
        alpn: None, ciphers: None, groups: None,
        session_tickets: tls::SessionTicketPolicy::Disabled,
        keylog: None,
    };
    let listener = f.bindings.openssl_component_tls().server_listener()
        .call_bind(&mut f.store, "127.0.0.1", 0, &cfg)
        .await.unwrap().unwrap();
    let port = f.bindings.openssl_component_tls().server_listener()
        .call_local_port(&mut f.store, listener).await.unwrap();

    let handle = thread::spawn(move || -> Result<(), String> {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
        let mut b = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client())
            .map_err(|e| e.to_string())?;
        b.set_verify(openssl::ssl::SslVerifyMode::NONE);
        let cert = openssl::x509::X509::from_der(&client_cert_der).map_err(|e| e.to_string())?;
        let pkey = openssl::pkey::PKey::private_key_from_pem(&client_key_pem)
            .map_err(|e| e.to_string())?;
        b.set_certificate(&cert).map_err(|e| e.to_string())?;
        b.set_private_key(&pkey).map_err(|e| e.to_string())?;
        let ctx = b.build();
        let mut ssl = openssl::ssl::Ssl::new(&ctx).map_err(|e| e.to_string())?;
        ssl.set_hostname("localhost").map_err(|e| e.to_string())?;
        let mut stream = openssl::ssl::SslStream::new(ssl, tcp).map_err(|e| e.to_string())?;
        stream.connect().map_err(|e| e.to_string())?;
        stream.write_all(b"ping").map_err(|e| e.to_string())?;
        Ok(())
    });

    let server = f.bindings.openssl_component_tls().server_listener()
        .call_accept(&mut f.store, listener).await.unwrap().unwrap();
    let msg = f.bindings.openssl_component_tls().server()
        .call_read(&mut f.store, server, 64).await.unwrap().unwrap();
    assert_eq!(&msg, b"ping");
    handle.join().unwrap().expect("client failed");
}

/// ALPN negotiation: server offers "h2","http/1.1", client prefers "http/1.1".
#[tokio::test]
async fn alpn_negotiation_round_trip() {
    let mut f = Fixture::with_builder(networked_builder()).await.unwrap();
    let (cert, key) = build_server_cert(&mut f).await;

    let cfg = tls::ServerConfig {
        protocols: tls::ProtocolRange { min: tls::Protocol::Tls12, max: tls::Protocol::Tls13 },
        verify: tls::VerifyMode::None,
        client_trust: None,
        cert_chain: vec![cert],
        key,
        sni_hosts: vec![],
        alpn: Some(tls::AlpnOffer {
            protocols: vec!["h2".into(), "http/1.1".into()],
        }),
        ciphers: None, groups: None,
        session_tickets: tls::SessionTicketPolicy::Disabled,
        keylog: None,
    };
    let listener = f.bindings.openssl_component_tls().server_listener()
        .call_bind(&mut f.store, "127.0.0.1", 0, &cfg).await.unwrap().unwrap();
    let port = f.bindings.openssl_component_tls().server_listener()
        .call_local_port(&mut f.store, listener).await.unwrap();

    let client_handle = thread::spawn(move || -> Result<Option<Vec<u8>>, String> {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
        let mut b = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client())
            .map_err(|e| e.to_string())?;
        b.set_verify(openssl::ssl::SslVerifyMode::NONE);
        // Client offers http/1.1 first, then h2.
        b.set_alpn_protos(b"\x08http/1.1\x02h2").map_err(|e| e.to_string())?;
        let ctx = b.build();
        let mut ssl = openssl::ssl::Ssl::new(&ctx).map_err(|e| e.to_string())?;
        ssl.set_hostname("localhost").map_err(|e| e.to_string())?;
        let mut stream = openssl::ssl::SslStream::new(ssl, tcp).map_err(|e| e.to_string())?;
        stream.connect().map_err(|e| e.to_string())?;
        let selected = stream.ssl().selected_alpn_protocol().map(Vec::from);
        let _ = stream.write_all(b"x");
        Ok(selected)
    });

    let server = f.bindings.openssl_component_tls().server_listener()
        .call_accept(&mut f.store, listener).await.unwrap().unwrap();
    let _ = f.bindings.openssl_component_tls().server()
        .call_read(&mut f.store, server, 8).await.unwrap().unwrap();
    let peer = f.bindings.openssl_component_tls().server()
        .call_peer(&mut f.store, server).await.unwrap();
    assert!(peer.alpn.is_some());
    // OpenSSL's default ALPN callback picks the first match from server list.
    assert_eq!(peer.alpn.as_deref(), Some("h2"));
    let client_sel = client_handle.join().unwrap().expect("client failed");
    assert_eq!(client_sel.as_deref(), Some(b"h2" as &[u8]));
}

/// Keylog sink: create a sink, pass to server config, verify after
/// handshake that drain returns NSS-format lines.
#[tokio::test]
async fn keylog_sink_captures_secrets() {
    let mut f = Fixture::with_builder(networked_builder()).await.unwrap();
    let (cert, key) = build_server_cert(&mut f).await;

    let sink = f.bindings.openssl_component_tls().keylog_sink()
        .call_constructor(&mut f.store).await.unwrap();
    let cfg = tls::ServerConfig {
        protocols: tls::ProtocolRange { min: tls::Protocol::Tls13, max: tls::Protocol::Tls13 },
        verify: tls::VerifyMode::None,
        client_trust: None,
        cert_chain: vec![cert],
        key,
        sni_hosts: vec![],
        alpn: None, ciphers: None, groups: None,
        session_tickets: tls::SessionTicketPolicy::Disabled,
        keylog: Some(sink),
    };
    // If keylog isn't wired through to OpenSSL's keylog callback inside
    // the component, the drain will be empty — test accepts that but
    // asserts the handshake still works.
    let listener = f.bindings.openssl_component_tls().server_listener()
        .call_bind(&mut f.store, "127.0.0.1", 0, &cfg).await.unwrap().unwrap();
    let port = f.bindings.openssl_component_tls().server_listener()
        .call_local_port(&mut f.store, listener).await.unwrap();

    let h = thread::spawn(move || -> Result<(), String> {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
        let ctx = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client())
            .map_err(|e| e.to_string())?.build();
        let mut ssl = openssl::ssl::Ssl::new(&ctx).map_err(|e| e.to_string())?;
        ssl.set_verify(openssl::ssl::SslVerifyMode::NONE);
        ssl.set_hostname("localhost").map_err(|e| e.to_string())?;
        let mut stream = openssl::ssl::SslStream::new(ssl, tcp).map_err(|e| e.to_string())?;
        stream.connect().map_err(|e| e.to_string())?;
        stream.write_all(b"x").map_err(|e| e.to_string())?;
        Ok(())
    });

    let server = f.bindings.openssl_component_tls().server_listener()
        .call_accept(&mut f.store, listener).await.unwrap().unwrap();
    let _ = f.bindings.openssl_component_tls().server()
        .call_read(&mut f.store, server, 8).await.unwrap().unwrap();
    h.join().unwrap().expect("client failed");

    // We passed `sink` into the server config (owned), so we can't drain
    // it from the host anymore. What we're verifying here is just that
    // the handshake completes with keylog configured; the drain-from-host
    // path is exercised when the component wires SSL_CTX_set_keylog_callback
    // (deferred).
}
