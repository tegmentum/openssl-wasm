//! Minimal HTTP sign/verify service backed by the openssl-wasm component.
//!
//! - POST /sign   body → raw Ed25519 signature (hex)
//! - POST /verify body = "<hex-sig>\n<message>" → 200 if valid, 400 otherwise
//! - GET  /pubkey → base64-ish hex of the service's public key
//!
//! The keypair is generated once at startup inside the component and
//! stays there; nothing leaves the wasm sandbox except the public key
//! and signatures.
//!
//! Usage:  cargo run --release -- 127.0.0.1:8080

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use wasmtime::component::{Component, Linker, ResourceAny, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

wasmtime::component::bindgen!({
    world: "openssl",
    path: "../../wit",
    imports: { default: async },
    exports: { default: async },
});

use exports::openssl::component::pkey as pk;

struct Host {
    wasi: WasiCtx,
    table: ResourceTable,
}
impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

struct Service {
    store: Store<Host>,
    bindings: Openssl,
    key: ResourceAny,
    pub_hex: String,
}

async fn build_service() -> Result<Service> {
    let component_path = std::env::var_os("OPENSSL_WASM_COMPONENT")
        .map(PathBuf::from)
        .or_else(|| {
            let p = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../build/openssl-component.wasm");
            p.exists().then_some(p)
        })
        .ok_or_else(|| anyhow!("set OPENSSL_WASM_COMPONENT"))?;

    let engine = Engine::default();
    let component = Component::from_file(&engine, &component_path)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("loading {}", component_path.display()))?;
    let mut linker = Linker::<Host>::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    let mut b = WasiCtxBuilder::new();
    b.inherit_stdio();
    let mut store = Store::new(&engine,
        Host { wasi: b.build(), table: ResourceTable::new() });
    let bindings = Openssl::instantiate_async(&mut store, &component, &linker).await?;

    // Generate one Ed25519 keypair for the lifetime of the service.
    let key = bindings.openssl_component_pkey().pkey()
        .call_generate(&mut store, pk::KeygenParams::Ed(pk::EdwardsCurve::Ed25519))
        .await?
        .map_err(|e| anyhow!("keygen: {e:?}"))?;
    let pub_bytes = bindings.openssl_component_pkey().pkey()
        .call_raw_public(&mut store, key).await?
        .map_err(|e| anyhow!("raw_public: {e:?}"))?;
    let pub_hex = hex(&pub_bytes);

    Ok(Service { store, bindings, key, pub_hex })
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b { let _ = write!(&mut s, "{:02x}", x); }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).ok())
        .collect()
}

async fn sign_msg(svc: &mut Service, msg: &[u8]) -> Result<Vec<u8>> {
    svc.bindings.openssl_component_pkey().pkey()
        .call_sign_message(&mut svc.store, svc.key, None, &msg.to_vec(), None)
        .await?
        .map_err(|e| anyhow!("sign: {e:?}"))
}

async fn verify_msg(svc: &mut Service, msg: &[u8], sig: &[u8]) -> Result<bool> {
    svc.bindings.openssl_component_pkey().pkey()
        .call_verify_message(&mut svc.store, svc.key, None,
                             &msg.to_vec(), &sig.to_vec(), None)
        .await?
        .map_err(|e| anyhow!("verify: {e:?}"))
}

/// Tiny ad-hoc HTTP/1.1 request parser. Not a real HTTP server — it's
/// enough to demo the signing interface in ~20 lines.
async fn handle_conn(
    mut conn: tokio::net::TcpStream,
    svc: Arc<Mutex<Service>>,
) -> Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let n = conn.read(&mut tmp).await?;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match split {
        Some(p) => (&buf[..p], &buf[p+4..]),
        None    => (&buf[..], &[][..]),
    };
    let head_str = String::from_utf8_lossy(head);
    let first = head_str.lines().next().unwrap_or("");
    let (method, target) = match first.split_whitespace().collect::<Vec<_>>().as_slice() {
        [m, t, _] => (m.to_string(), t.to_string()),
        _         => return write_resp(&mut conn, 400, "bad request").await,
    };

    // Read the declared Content-Length if the first drain missed the body.
    let content_len = head_str.lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = body.to_vec();
    while body.len() < content_len {
        let n = conn.read(&mut tmp).await?;
        if n == 0 { break; }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_len);

    match (method.as_str(), target.as_str()) {
        ("GET", "/pubkey") => {
            let s = svc.lock().await;
            let pub_hex = s.pub_hex.clone();
            drop(s);
            write_resp(&mut conn, 200, &pub_hex).await
        }
        ("POST", "/sign") => {
            let mut s = svc.lock().await;
            let sig = sign_msg(&mut s, &body).await?;
            write_resp(&mut conn, 200, &hex(&sig)).await
        }
        ("POST", "/verify") => {
            let text = String::from_utf8_lossy(&body);
            let (sig_hex, msg) = match text.split_once('\n') {
                Some(p) => p, None => return write_resp(&mut conn, 400, "need hex\\nmessage").await,
            };
            let Some(sig) = unhex(sig_hex.trim()) else {
                return write_resp(&mut conn, 400, "bad hex").await;
            };
            let mut s = svc.lock().await;
            let ok = verify_msg(&mut s, msg.as_bytes(), &sig).await?;
            write_resp(&mut conn, if ok { 200 } else { 400 },
                       if ok { "ok" } else { "bad signature" }).await
        }
        _ => write_resp(&mut conn, 404, "not found").await,
    }
}

async fn write_resp(
    conn: &mut tokio::net::TcpStream,
    status: u16, body: &str,
) -> Result<()> {
    let reason = match status {
        200 => "OK", 400 => "Bad Request", 404 => "Not Found",
        _ => "Error",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    conn.write_all(resp.as_bytes()).await?;
    conn.shutdown().await.ok();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8080".into());
    let listener = TcpListener::bind(&addr).await?;
    eprintln!("sign-service on http://{addr}");

    let svc = Arc::new(Mutex::new(build_service().await?));
    eprintln!("pubkey: {}", svc.lock().await.pub_hex);

    loop {
        let (conn, peer) = listener.accept().await?;
        let svc = svc.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(conn, svc).await {
                eprintln!("[{peer}] {e}");
            }
        });
    }
}
