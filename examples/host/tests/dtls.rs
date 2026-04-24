//! DTLS is defined in the WIT enum but not implemented in the
//! component. It's wired to fail fast (`TlsError::ProtocolVersion`)
//! rather than silently fall back to TLS, which would confuse callers
//! requesting specifically DTLS.
//!
//! A real implementation would need BIO_s_datagram + UDP socket setup
//! + DTLS_client_method / DTLS_server_method, all depending on
//! wasi:sockets UDP support. Deferred.

use openssl_wasm_host::{Fixture, exports};
use exports::openssl::component::tls;

#[tokio::test]
async fn dtls_request_rejected_cleanly() {
    let mut f = Fixture::new().await.unwrap();

    let cfg = tls::ClientConfig {
        protocols: tls::ProtocolRange {
            min: tls::Protocol::Dtls12,
            max: tls::Protocol::Dtls12,
        },
        verify: tls::VerifyMode::None,
        trust: None,
        verify_options: None,
        server_name: Some("example.com".into()),
        client_cert: None, client_key: None,
        alpn: None, ciphers: None, groups: None,
        enable_early_data: false, resume_session: None,
        keylog: false,
    };

    let r = f.bindings.openssl_component_tls().client()
        .call_connect(&mut f.store, "127.0.0.1", 0, &cfg)
        .await.unwrap();

    match r {
        Err(tls::TlsError::ProtocolVersion) => {}
        Err(e) => panic!("expected ProtocolVersion, got {e:?}"),
        Ok(_) => panic!("DTLS should not succeed silently via TLS"),
    }
}
