//! Demo runner. The test suite lives in tests/. This binary just
//! exercises a few interfaces interactively so you can see output.

use std::path::PathBuf;

use anyhow::{Result, anyhow};
use openssl_wasm_host::{Fixture, exports, hex};
use wasmtime_wasi::WasiCtxBuilder;

#[tokio::main]
async fn main() -> Result<()> {
    if let Some(p) = std::env::args_os().nth(1) {
        unsafe { std::env::set_var("OPENSSL_WASM_COMPONENT", p); }
    } else {
        let fallback: PathBuf = "build/openssl-component.wasm".into();
        if fallback.exists() {
            unsafe {
                std::env::set_var("OPENSSL_WASM_COMPONENT",
                    fallback.canonicalize()?);
            }
        }
    }

    // Networked fixture so we can smoke-test TLS.
    let mut b = WasiCtxBuilder::new();
    b.inherit_stdio().inherit_network().allow_ip_name_lookup(true);
    let mut f = Fixture::with_builder(b).await?;

    use exports::openssl::component::digest::Algorithm;
    let input = b"hello, wasm\n".to_vec();
    let out = f.bindings
        .openssl_component_digest()
        .call_one_shot(&mut f.store, Algorithm::Sha256, &input)
        .await?
        .map_err(|e| anyhow!("digest: {e:?}"))?;
    println!("sha256({:?}) = {}",
        String::from_utf8_lossy(&input), hex(&out));

    // TLS smoke.
    use exports::openssl::component::tls;
    let cfg = tls::ClientConfig {
        protocols: tls::ProtocolRange { min: tls::Protocol::Tls12, max: tls::Protocol::Tls13 },
        verify: tls::VerifyMode::None,
        trust: None,
        verify_options: None,
        server_name: Some("example.com".into()),
        client_cert: None,
        client_key: None,
        alpn: None,
        ciphers: None,
        groups: None,
        enable_early_data: false,
        resume_session: None,
        keylog: false,
    };
    let client = f.bindings
        .openssl_component_tls()
        .client()
        .call_connect(&mut f.store, "example.com", 443, &cfg)
        .await?
        .map_err(|e| anyhow!("tls connect: {e:?}"))?;
    let req = b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    f.bindings.openssl_component_tls().client()
        .call_write(&mut f.store, client, req).await?
        .map_err(|e| anyhow!("tls write: {e:?}"))?;
    let resp = f.bindings.openssl_component_tls().client()
        .call_read(&mut f.store, client, 256).await?
        .map_err(|e| anyhow!("tls read: {e:?}"))?;
    let text = String::from_utf8_lossy(&resp);
    let first_line = text.split('\n').next().unwrap_or("").trim();
    println!("tls first line: {first_line}");

    Ok(())
}
