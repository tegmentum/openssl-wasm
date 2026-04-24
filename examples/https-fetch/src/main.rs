//! HTTPS fetcher: do a full TLS + HTTP/1.1 GET inside the wasm
//! component against a user-supplied URL, print the response.
//!
//! Usage:
//!     cargo run --release -- https://example.com/
//!
//! Host needs `OPENSSL_WASM_COMPONENT=<path>` pointing at
//! `build/openssl-component.wasm` (or the cargo working directory
//! has the default `../../build/openssl-component.wasm`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{
    DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView,
};

wasmtime::component::bindgen!({
    world: "openssl",
    path: "../../wit",
    imports: { default: async },
    exports: { default: async },
});

use exports::openssl::component::tls;
use exports::openssl::component::x509;

struct Host {
    wasi: WasiCtx,
    table: ResourceTable,
}
impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

fn find_ca_bundle() -> Option<PathBuf> {
    for p in [
        "/etc/ssl/cert.pem",
        "/opt/homebrew/etc/ca-certificates/cert.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/certs/ca-certificates.crt",
    ] {
        let pb = PathBuf::from(p);
        if pb.exists() { return Some(pb); }
    }
    None
}

fn parse_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url.strip_prefix("https://")
        .ok_or_else(|| anyhow!("URL must start with https://"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None    => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse()?),
        None         => (hostport.to_string(), 443u16),
    };
    Ok((host, port, path.to_string()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let url = std::env::args().nth(1).unwrap_or_else(|| "https://example.com/".into());
    let (host, port, path) = parse_url(&url)?;

    let component_path = std::env::var_os("OPENSSL_WASM_COMPONENT")
        .map(PathBuf::from)
        .or_else(|| {
            let p = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../build/openssl-component.wasm");
            p.exists().then_some(p)
        })
        .ok_or_else(|| anyhow!("set OPENSSL_WASM_COMPONENT or build the component"))?;

    let ca = find_ca_bundle().ok_or_else(|| anyhow!("no CA bundle on this host"))?;
    let ca_dir = ca.parent().unwrap();
    let ca_name = ca.file_name().unwrap().to_str().unwrap().to_string();
    eprintln!("# CA bundle: {} (via preopen /ca/{})", ca.display(), ca_name);

    let engine = Engine::default();
    let component = Component::from_file(&engine, &component_path)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("loading {}", component_path.display()))?;
    let mut linker = Linker::<Host>::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    let mut wb = WasiCtxBuilder::new();
    wb.inherit_stdio()
        .inherit_network()
        .allow_ip_name_lookup(true)
        .preopened_dir(ca_dir, "/ca", DirPerms::READ, FilePerms::READ)?;
    let mut store = Store::new(&engine,
        Host { wasi: wb.build(), table: ResourceTable::new() });
    let bindings = Openssl::instantiate_async(&mut store, &component, &linker).await?;

    // Build a trust store from the system CA bundle.
    let store_h = bindings.openssl_component_x509().store()
        .call_constructor(&mut store).await?;
    bindings.openssl_component_x509().store()
        .call_load_from_file(&mut store, store_h, &format!("/ca/{ca_name}")).await?
        .map_err(|e| anyhow!("load_from_file: {e:?}"))?;

    let cfg = tls::ClientConfig {
        protocols: tls::ProtocolRange { min: tls::Protocol::Tls12, max: tls::Protocol::Tls13 },
        verify: tls::VerifyMode::Required,
        trust: Some(store_h),
        verify_options: Some(x509::VerifyOptions {
            hostname: Some(host.clone()),
            ip: None,
            purpose: Some(x509::ExtendedKeyUsage::ServerAuth),
            at: None, partial_chain: false,
            crl_check: false, crl_check_all: false,
        }),
        server_name: Some(host.clone()),
        client_cert: None, client_key: None,
        alpn: None, ciphers: None, groups: None,
        enable_early_data: false, resume_session: None, keylog: None,
    };
    let client = bindings.openssl_component_tls().client()
        .call_connect(&mut store, &host, port, &cfg).await?
        .map_err(|e| anyhow!("connect: {e:?}"))?;

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: openssl-wasm-example\r\nConnection: close\r\n\r\n"
    );
    bindings.openssl_component_tls().client()
        .call_write(&mut store, client, req.as_bytes()).await?
        .map_err(|e| anyhow!("write: {e:?}"))?;

    // Drain the response. Keep reading until the peer closes.
    let mut body = Vec::new();
    loop {
        let chunk = bindings.openssl_component_tls().client()
            .call_read(&mut store, client, 4096).await?
            .map_err(|e| anyhow!("read: {e:?}"))?;
        if chunk.is_empty() { break; }
        body.extend_from_slice(&chunk);
        if body.len() > 256 * 1024 {
            break; // sanity cap
        }
    }

    let peer = bindings.openssl_component_tls().client()
        .call_peer(&mut store, client).await?;
    eprintln!("# {} {} (chain: {} certs){}{}",
        match peer.protocol { tls::Protocol::Tls13 => "TLS 1.3",
                              tls::Protocol::Tls12 => "TLS 1.2",
                              _ => "other" },
        peer.cipher_suite,
        peer.peer_chain.len(),
        peer.group.as_deref().map(|g| format!(" group={g}")).unwrap_or_default(),
        if peer.resumed { " [resumed]" } else { "" },
    );
    print!("{}", String::from_utf8_lossy(&body));
    Ok(())
}
