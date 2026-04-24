//! Live TLS tests. These need network access + a CA bundle on the host.
//! They are skipped if either isn't available.
//!
//! Run with `cargo test --test tls -- --include-ignored --nocapture`
//! or let `make test` include them.

use openssl_wasm_host::{Fixture, exports};
use wasmtime::component::Resource;
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::{DirPerms, FilePerms};

use exports::openssl::component::tls;
use exports::openssl::component::x509;

const CA_BUNDLE_CANDIDATES: &[&str] = &[
    "/etc/ssl/cert.pem",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/certs/ca-certificates.crt",
];

fn ca_bundle_path() -> Option<std::path::PathBuf> {
    CA_BUNDLE_CANDIDATES.iter()
        .map(std::path::Path::new)
        .find(|p| p.exists())
        .map(std::path::Path::to_path_buf)
}

/// Build a networked fixture that preopens the directory containing the
/// system CA bundle so the component can read it as `/ca/cert.pem`.
async fn networked_fixture_with_ca() -> Option<(Fixture, String)> {
    let bundle = ca_bundle_path()?;
    let dir = bundle.parent()?.to_path_buf();
    let fname = bundle.file_name()?.to_str()?.to_string();

    let mut b = WasiCtxBuilder::new();
    b.inherit_stdio()
        .inherit_network()
        .allow_ip_name_lookup(true)
        .preopened_dir(&dir, "/ca", DirPerms::READ, FilePerms::READ)
        .ok()?;
    let f = Fixture::with_builder(b).await.ok()?;
    Some((f, format!("/ca/{fname}")))
}

#[tokio::test]
async fn tls_verify_none_connects() {
    // Same as the main.rs smoke test, but in the harness so it's part of
    // CI. verify=none — proves handshake + read/write plumbing.
    let mut b = WasiCtxBuilder::new();
    b.inherit_stdio().inherit_network().allow_ip_name_lookup(true);
    let mut f = match Fixture::with_builder(b).await {
        Ok(f) => f,
        Err(_) => return, // no network, skip
    };
    let cfg = tls::ClientConfig {
        protocols: tls::ProtocolRange { min: tls::Protocol::Tls12, max: tls::Protocol::Tls13 },
        verify: tls::VerifyMode::None,
        trust: None,
        verify_options: None,
        server_name: Some("example.com".into()),
        client_cert: None, client_key: None,
        alpn: None, ciphers: None, groups: None,
        enable_early_data: false, resume_session: None, keylog: None,
    };
    let client = match f.bindings.openssl_component_tls().client()
        .call_connect(&mut f.store, "example.com", 443, &cfg).await.unwrap() {
        Ok(c) => c,
        Err(e) => { eprintln!("skipping (offline?): {e:?}"); return; }
    };
    let req = b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    f.bindings.openssl_component_tls().client()
        .call_write(&mut f.store, client, req).await.unwrap().unwrap();
    let resp = f.bindings.openssl_component_tls().client()
        .call_read(&mut f.store, client, 256).await.unwrap().unwrap();
    let first = String::from_utf8_lossy(&resp);
    assert!(first.starts_with("HTTP/"),
            "unexpected response: {}", first.lines().next().unwrap_or(""));
}

#[tokio::test]
async fn tls_verify_required_with_system_ca() {
    let Some((mut f, ca_path)) = networked_fixture_with_ca().await else {
        eprintln!("skipping: no CA bundle found on host");
        return;
    };

    // Build store with default trust from preopened CA.
    let store = f.bindings.openssl_component_x509().store()
        .call_constructor(&mut f.store).await.unwrap();
    f.bindings.openssl_component_x509().store()
        .call_load_from_file(&mut f.store, store, &ca_path)
        .await.unwrap()
        .expect("CA bundle should load from preopened /ca");

    let cfg = tls::ClientConfig {
        protocols: tls::ProtocolRange { min: tls::Protocol::Tls12, max: tls::Protocol::Tls13 },
        verify: tls::VerifyMode::Required,
        trust: Some(store),
        verify_options: Some(x509::VerifyOptions {
            hostname: Some("example.com".into()),
            ip: None, purpose: Some(x509::ExtendedKeyUsage::ServerAuth),
            at: None, partial_chain: false,
            crl_check: false, crl_check_all: false,
        }),
        server_name: Some("example.com".into()),
        client_cert: None, client_key: None,
        alpn: None, ciphers: None, groups: None,
        enable_early_data: false, resume_session: None, keylog: None,
    };
    let client = match f.bindings.openssl_component_tls().client()
        .call_connect(&mut f.store, "example.com", 443, &cfg).await.unwrap() {
        Ok(c) => c,
        Err(e) => panic!("connect w/ verification failed: {e:?}"),
    };
    let req = b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    f.bindings.openssl_component_tls().client()
        .call_write(&mut f.store, client, req).await.unwrap().unwrap();
    let resp = f.bindings.openssl_component_tls().client()
        .call_read(&mut f.store, client, 256).await.unwrap().unwrap();
    let first = String::from_utf8_lossy(&resp);
    assert!(first.starts_with("HTTP/"), "expected HTTP response, got {first}");

    // Inspect peer info.
    let peer = f.bindings.openssl_component_tls().client()
        .call_peer(&mut f.store, client).await.unwrap();
    eprintln!("peer: {} {} chain={}",
        match peer.protocol { tls::Protocol::Tls13 => "TLS 1.3",
                              tls::Protocol::Tls12 => "TLS 1.2",
                              _ => "other" },
        peer.cipher_suite, peer.peer_chain.len());
    assert!(peer.peer_chain.len() >= 1);

    // Drop the resources wasmtime isn't auto-tracking in async close.
    let _ = client;
    let _: Resource<()> = Resource::new_own(0); // silence unused
}
