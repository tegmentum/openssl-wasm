//! Phase 5.4: real TLS handshake using a wit-bridge-backed server key.
//!
//! Composes openssl-wasm + simple-provider-adapter + pkcs11-bridge +
//! pkcs11-provider + softhsm2.component, has the wasm component bind
//! a TLS listener with the server's private key resolved from a
//! `pkcs11:slot-id=0;...;init=true` URI (so SoftHSM auto-provisions
//! a fresh ECDSA P-256 key on first use), then has a native
//! openssl-rs client connect and complete the handshake.
//!
//! This is the marquee Phase 5 done-when: openssl signed the TLS
//! handshake using a private key that never left a PKCS#11 token
//! (here, SoftHSM compiled to wasm).
//!
//! Compose with scripts/compose-pkcs11-stack.sh (TODO) and run:
//!
//!   OPENSSL_WASM_COMPONENT=/tmp/owasm-full.wasm \
//!     cargo test --release --test tls_pkcs11

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::thread;

use anyhow::{anyhow, Result};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::{
    DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView,
};

wasmtime::component::bindgen!({
    path: "tests/wit_tls",
    world: "phase5-tls",
    imports: { default: async },
    exports: { default: async },
});

use exports::openssl::component::{digest, pkey, tls, x509};

struct State {
    table: ResourceTable,
    ctx: WasiCtx,
}
impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.ctx, table: &mut self.table }
    }
}

impl pkcs11::util::util::Host for State {}
impl pkcs11::util::util::HostPinProvider for State {
    async fn request_secret(
        &mut self,
        _self_: wasmtime::component::Resource<pkcs11::util::util::PinProvider>,
        _label: Option<String>,
        _attempts_remaining: Option<u8>,
    ) -> Vec<u8> { Vec::new() }
    async fn clear(&mut self, _: wasmtime::component::Resource<pkcs11::util::util::PinProvider>) {}
    async fn drop(&mut self, _: wasmtime::component::Resource<pkcs11::util::util::PinProvider>) -> wasmtime::Result<()> { Ok(()) }
}

fn stage_softhsm_dirs() -> Result<(PathBuf, PathBuf)> {
    let run = std::env::temp_dir()
        .join(format!("tls-pkcs11-{}", std::process::id()));
    let cfg_dir  = run.join("config");
    let data_dir = run.join("data");
    std::fs::create_dir_all(&cfg_dir)?;
    std::fs::create_dir_all(data_dir.join("tokens"))?;
    let conf = b"directories.tokendir = /data/tokens\n\
                 objectstore.backend = file\n\
                 objectstore.umask = 0077\n\
                 log.level = INFO\n\
                 slots.removable = false\n\
                 slots.mechanisms = ALL\n\
                 library.reset_on_fork = false\n";
    std::fs::write(cfg_dir.join("softhsm2-wasi.conf"), conf)?;
    Ok((cfg_dir, data_dir))
}

#[tokio::test]
async fn tls_server_with_pkcs11_key() -> Result<()> {
    let comp_path = std::env::var("OPENSSL_WASM_COMPONENT")
        .map_err(|_| anyhow!(
            "set OPENSSL_WASM_COMPONENT to the composed full-stack wasm"))?;
    let comp_path = PathBuf::from(comp_path);
    if !Path::new(&comp_path).exists() {
        return Err(anyhow!("component not found: {}", comp_path.display()));
    }

    let (cfg_dir, data_dir) = stage_softhsm_dirs()?;

    let mut engine_cfg = Config::new();
    engine_cfg.wasm_component_model(true);
    engine_cfg.async_support(true);
    let engine = Engine::new(&engine_cfg)?;
    let component = Component::from_file(&engine, &comp_path)?;

    let guest_stderr = MemoryOutputPipe::new(4 << 20);
    let mut wasi = WasiCtxBuilder::new();
    wasi.inherit_stdin()
        .inherit_stdout()
        .stderr(guest_stderr.clone())
        .inherit_network()
        .allow_ip_name_lookup(true)
        .env("SOFTHSM2_CONF", "/config/softhsm2-wasi.conf")
        .preopened_dir(&cfg_dir,  "/config", DirPerms::READ, FilePerms::READ)?
        .preopened_dir(&data_dir, "/data",   DirPerms::all(), FilePerms::all())?;
    let state = State { table: ResourceTable::new(), ctx: wasi.build() };

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    pkcs11::util::util::add_to_linker::<State, wasmtime::component::HasSelf<State>>(
        &mut linker, |s| s,
    )?;
    let mut store = Store::new(&engine, state);
    let bindings = Phase5Tls::instantiate_async(&mut store, &component, &linker).await?;

    let result = run_handshake(&mut store, &bindings, guest_stderr.clone()).await;
    drop((cfg_dir, data_dir));
    result
}

async fn run_handshake(
    store: &mut Store<State>,
    bindings: &Phase5Tls,
    guest_stderr: MemoryOutputPipe,
) -> Result<()> {
    let pk = bindings.openssl_component_pkey().pkey();
    let xcomp = bindings.openssl_component_x509();
    let tlsc = bindings.openssl_component_tls();

    // 1. Get the wit-bridge-backed key from the PKCS#11 URI. This is
    //    the key TLS will use to sign the handshake.
    let uri = "pkcs11:slot-id=0;object=phase-5-tls-key;pin-value=1234;\
               init=true;algorithm=ecdsa-p256".to_string();
    let server_key = pk.call_from_wit_bridge_uri(&mut *store, &uri).await?
        .map_err(|e| anyhow!("from-wit-bridge-uri: {e:?}"))?;
    println!("[1] obtained wit-bridge EVP_PKEY for {uri:?}");

    // 2. Build a cert whose SubjectPublicKey is the wit-bridge key,
    //    but signed by a regular generated Ed25519 key.
    //
    //    Why two keys: X509_sign internally uses EVP_DigestSign with
    //    propq=NULL. OpenSSL's keymgmt-match for export-to-provider
    //    then falls to the default provider's keymgmt, which can't
    //    operate on a wit-bridge-backed keydata. EVP_PKEY_sign (used
    //    by TLS's CertVerify path with an explicit ctx) doesn't have
    //    this problem.
    //
    //    Test uses VerifyMode::None so the client doesn't validate
    //    the cert chain; what matters for the handshake is that
    //    SubjectPublicKey matches whatever signs the CertVerify --
    //    both are the wit-bridge key.
    let cert_signer = pk.call_generate(&mut *store,
        pkey::KeygenParams::Ed(pkey::EdwardsCurve::Ed25519))
        .await?.map_err(|e| anyhow!("gen cert-signer: {e:?}"))?;
    // build_and_sign takes subject_key by OWNED pkey -- clone our
    // wit-bridge handle so server_key stays alive for the TLS config.
    let subject_key = pk.call_clone(&mut *store, server_key).await?;
    let subject = vec![x509::NameEntry { oid: "CN".into(), value: "localhost".into() }];
    let builder = x509::CertificateBuilderInput {
        subject: subject.clone(),
        issuer: subject,
        serial_hex: Some("01".into()),
        validity: x509::Validity {
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after:  "2099-01-01T00:00:00Z".into(),
        },
        subject_alt_names: vec![
            x509::GeneralName::Dns("localhost".into()),
            x509::GeneralName::Ip(vec![127, 0, 0, 1]),
        ],
        key_usage: Some(x509::KeyUsage::DIGITAL_SIGNATURE),
        extended_key_usage: vec![x509::ExtendedKeyUsage::ServerAuth],
        basic_constraints: None,
        subject_key,
        signature_hash: digest::Algorithm::Sha512,
    };
    let cert = xcomp.call_build_and_sign(&mut *store, &builder, cert_signer).await?
        .map_err(|e| anyhow!("build_and_sign: {e:?}"))?;
    println!("[2] cert built; subject pubkey = wit-bridge, signed by ed25519");
    let _ = digest::Algorithm::Sha256; // silence unused-import

    // 3. TLS server: bind listener.
    let cfg = tls::ServerConfig {
        protocols: tls::ProtocolRange { min: tls::Protocol::Tls12, max: tls::Protocol::Tls13 },
        verify: tls::VerifyMode::None,
        client_trust: None,
        cert_chain: vec![cert],
        key: server_key,
        sni_hosts: vec![],
        alpn: None, ciphers: None, groups: None,
        session_tickets: tls::SessionTicketPolicy::Disabled,
        keylog: false,
    };
    let listener = tlsc.server_listener().call_bind(&mut *store, "127.0.0.1", 0, &cfg).await?
        .map_err(|e| anyhow!("bind: {e:?}"))?;
    let port = tlsc.server_listener().call_local_port(&mut *store, listener).await?;
    println!("[3] TLS listener bound on 127.0.0.1:{port}");

    // 4. Spawn host-OS thread that connects + does TLS handshake +
    //    sends/receives a message.
    let client = thread::spawn(move || -> Result<Vec<u8>, String> {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .map_err(|e| format!("connect: {e}"))?;
        let ctx = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client())
            .map_err(|e| e.to_string())?.build();
        let mut ssl = openssl::ssl::Ssl::new(&ctx).map_err(|e| e.to_string())?;
        ssl.set_verify(openssl::ssl::SslVerifyMode::NONE);
        ssl.set_hostname("localhost").map_err(|e| e.to_string())?;
        let mut stream = openssl::ssl::SslStream::new(ssl, tcp)
            .map_err(|e| e.to_string())?;
        stream.connect().map_err(|e| format!("handshake: {e}"))?;
        stream.write_all(b"hello pkcs11 server").map_err(|e| e.to_string())?;
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
        Ok(buf[..n].to_vec())
    });

    // 5. Server side: accept, read, echo.
    let conn = tlsc.server_listener().call_accept(&mut *store, listener).await?
        .map_err(|e| anyhow!("accept: {e:?}"))?;
    println!("[4] TLS handshake completed");
    let req = tlsc.server().call_read(&mut *store, conn, 256).await?
        .map_err(|e| anyhow!("server read: {e:?}"))?;
    println!("    server read {} bytes from client", req.len());
    let _ = tlsc.server().call_write(&mut *store, conn, b"hello from wit-bridge tls server")
        .await?
        .map_err(|e| anyhow!("server write: {e:?}"))?;
    let _ = tlsc.server().call_close(&mut *store, conn).await;

    // 6. Join client.
    let echoed = client.join()
        .map_err(|_| anyhow!("client thread panicked"))?
        .map_err(|e| {
            let logs = guest_stderr.contents();
            if !logs.is_empty() {
                eprintln!("--- guest stderr ---");
                eprint!("{}", String::from_utf8_lossy(&logs));
            }
            anyhow!("client error: {e}")
        })?;
    println!("[5] client received {} bytes: {:?}",
             echoed.len(), String::from_utf8_lossy(&echoed));
    assert_eq!(req, b"hello pkcs11 server");
    assert!(echoed.starts_with(b"hello from wit-bridge"));

    println!("\nPHASE 5.4 -- TLS handshake completed against a wit-bridge \
              (PKCS#11/SoftHSM) backed server key. Private key never left \
              the wasm-sandboxed SoftHSM token.");
    Ok(())
}
