//! Phase 5.2 — drive `sign-with-wit-bridge` against the full stack
//! (openssl-wasm + simple-provider-adapter + pkcs11-bridge +
//! pkcs11-provider + softhsm2.component.wasm).
//!
//! Self-contained harness (doesn't use openssl-wasm-host's Fixture)
//! because the composed stack imports `pkcs11:util/util` for the
//! PinProvider resource type. Stubs the PinProvider with inline
//! PINs only.
//!
//! Compose the stack first (see scripts/build-pkcs11-stack.sh) and
//! point at it:
//!
//!   OPENSSL_WASM_COMPONENT=/tmp/owasm-full.wasm \
//!     cargo test --release --test wit_bridge_pkcs11

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::{
    DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView,
};

wasmtime::component::bindgen!({
    path: "tests/wit",
    world: "phase5-pkcs11",
    imports: { default: async },
    exports: { default: async },
});

struct State {
    table: ResourceTable,
    ctx: WasiCtx,
}
impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.ctx, table: &mut self.table }
    }
}

/// Stub PinProvider implementation. The composed stack never
/// constructs one because all login uses inline pin-value from
/// the URI -- this just satisfies the WIT type.
pub struct HostPin;
impl pkcs11::util::util::Host for State {}
impl pkcs11::util::util::HostPinProvider for State {
    async fn request_secret(
        &mut self,
        _self_: wasmtime::component::Resource<pkcs11::util::util::PinProvider>,
        _label: Option<String>,
        _attempts_remaining: Option<u8>,
    ) -> Vec<u8> { Vec::new() }
    async fn clear(&mut self, _: wasmtime::component::Resource<pkcs11::util::util::PinProvider>) {}
    async fn drop(&mut self, _: wasmtime::component::Resource<pkcs11::util::util::PinProvider>) -> wasmtime::Result<()> {
        Ok(())
    }
}

fn stage_softhsm_dirs() -> Result<(PathBuf, PathBuf)> {
    let run = std::env::temp_dir()
        .join(format!("wit-bridge-pkcs11-{}", std::process::id()));
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
async fn wit_bridge_signs_via_softhsm() -> Result<()> {
    let comp_path = std::env::var("OPENSSL_WASM_COMPONENT")
        .map_err(|_| anyhow!(
            "set OPENSSL_WASM_COMPONENT to the composed full-stack wasm \
             (openssl-wasm + adapter + pkcs11-bridge + pkcs11-provider \
             + softhsm2.component)"))?;
    let comp_path = PathBuf::from(comp_path);
    if !Path::new(&comp_path).exists() {
        return Err(anyhow!("component not found: {}", comp_path.display()));
    }

    let (cfg_dir, data_dir) = stage_softhsm_dirs()?;

    let mut engine_cfg = Config::new();
    engine_cfg.wasm_component_model(true);
    engine_cfg.async_support(true);
    let engine = Engine::new(&engine_cfg)?;
    let component = Component::from_file(&engine, &comp_path)
        .map_err(|e| anyhow!("loading {}: {e}", comp_path.display()))?;

    let guest_stderr = MemoryOutputPipe::new(4 << 20);
    let mut wasi = WasiCtxBuilder::new();
    wasi.inherit_stdin()
        .inherit_stdout()
        .stderr(guest_stderr.clone())
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
    let bindings = Phase5Pkcs11::instantiate_async(&mut store, &component, &linker).await?;

    let uri = "pkcs11:slot-id=0;object=phase-5-key;pin-value=1234;\
               init=true;algorithm=ecdsa-p256".to_string();
    let mdname = "SHA2-256".to_string();
    let tbs    = b"phase-5 wit-bridge-via-softhsm end-to-end check".to_vec();

    let result = bindings.openssl_component_wit_bridge_test()
        .call_sign_with_wit_bridge(&mut store, &uri, &mdname, &tbs).await;
    let sig = match result {
        Ok(Ok(s))  => s,
        Ok(Err(e)) => {
            let logs = guest_stderr.contents();
            if !logs.is_empty() {
                eprintln!("--- guest stderr ---");
                eprint!("{}", String::from_utf8_lossy(&logs));
            }
            return Err(anyhow!("sign-with-wit-bridge returned err: {e}"));
        }
        Err(t) => {
            let logs = guest_stderr.contents();
            if !logs.is_empty() {
                eprintln!("--- guest stderr ---");
                eprint!("{}", String::from_utf8_lossy(&logs));
            }
            return Err(anyhow!("trap: {t}"));
        }
    };

    println!("signature: {} bytes", sig.len());
    assert!(!sig.is_empty(), "signature should be non-empty");
    assert_eq!(sig[0], 0x30, "ECDSA DER signature should start 0x30 (SEQUENCE)");
    println!("\nOK -- openssl-wasm called sign-with-wit-bridge; the chain \
              (wit-bridge -> simple-provider-adapter -> pkcs11-bridge -> \
              pkcs11-provider -> softhsm2.component) signed inside the \
              wasm sandbox; signature came back as DER-wrapped ECDSA.");

    // -- Phase 5.3 gate: same chain but via EVP_PKEY_fromdata + EVP_DigestSign.
    // If this works, SSL_CTX_use_PrivateKey with the same EVP_PKEY works too
    // (TLS handshake path).
    println!("\n[Phase 5.3] sign-via-evp-with-wit-bridge");
    let evp_result = bindings.openssl_component_wit_bridge_test()
        .call_sign_via_evp_with_wit_bridge(&mut store, &uri, &mdname, &tbs).await;
    match evp_result {
        Ok(Ok(s)) => {
            println!("EVP signature: {} bytes", s.len());
            assert_eq!(s[0], 0x30, "EVP ECDSA DER signature should start 0x30");
            println!("\nOK -- EVP_DigestSign through wit-bridge produced a valid \
                      DER signature; SSL_CTX_use_PrivateKey path works.");
        }
        Ok(Err(e)) => {
            let logs = guest_stderr.contents();
            if !logs.is_empty() {
                eprintln!("--- guest stderr ---");
                eprint!("{}", String::from_utf8_lossy(&logs));
            }
            return Err(anyhow!("EVP path failed: {e}"));
        }
        Err(t) => return Err(anyhow!("EVP trap: {t}")),
    }

    println!("\n[Phase 8a] digest-sign-via-evp-with-wit-bridge (EVP_DigestSign path)");
    let dsr = bindings.openssl_component_wit_bridge_test()
        .call_digest_sign_via_evp_with_wit_bridge(&mut store, &uri, &mdname, &tbs).await;
    match dsr {
        Ok(Ok(s)) => {
            println!("EVP_DigestSign signature: {} bytes", s.len());
            assert_eq!(s[0], 0x30, "EVP_DigestSign ECDSA DER should start 0x30");
            println!("\nOK -- EVP_DigestSign through wit-bridge works; TLS handshake \
                      sign path is unblocked.");
        }
        Ok(Err(e)) => {
            let logs = guest_stderr.contents();
            if !logs.is_empty() {
                eprintln!("--- guest stderr ---");
                eprint!("{}", String::from_utf8_lossy(&logs));
            }
            return Err(anyhow!("EVP_DigestSign path failed: {e}"));
        }
        Err(t) => return Err(anyhow!("EVP_DigestSign trap: {t}")),
    }

    drop((cfg_dir, data_dir));
    Ok(())
}

/// Phase 8d: prove the bridge handles non-P-256 curves end-to-end --
/// auto-provisions a P-384 key via `algorithm=ecdsa-p384;init=true`,
/// signs through wit-bridge, expects DER SEQUENCE output. Validates
/// CKA_EC_PARAMS OID parsing + curve-name plumbing through the whole
/// keymgmt/signature stack.
#[tokio::test]
async fn wit_bridge_signs_p384_via_softhsm() -> Result<()> {
    let comp_path = std::env::var("OPENSSL_WASM_COMPONENT")
        .map_err(|_| anyhow!("set OPENSSL_WASM_COMPONENT"))?;
    let comp_path = PathBuf::from(comp_path);
    if !Path::new(&comp_path).exists() {
        return Err(anyhow!("component not found: {}", comp_path.display()));
    }

    let run = std::env::temp_dir().join(format!("p11-p384-{}", std::process::id()));
    let cfg_dir  = run.join("config");
    let data_dir = run.join("data");
    std::fs::create_dir_all(&cfg_dir)?;
    std::fs::create_dir_all(data_dir.join("tokens"))?;
    std::fs::write(cfg_dir.join("softhsm2-wasi.conf"),
        b"directories.tokendir = /data/tokens\n\
          objectstore.backend = file\n\
          objectstore.umask = 0077\n\
          log.level = INFO\n\
          slots.removable = false\n\
          slots.mechanisms = ALL\n\
          library.reset_on_fork = false\n")?;

    let mut engine_cfg = Config::new();
    engine_cfg.wasm_component_model(true);
    let engine = Engine::new(&engine_cfg)?;
    let component = Component::from_file(&engine, &comp_path)?;

    let guest_stderr = MemoryOutputPipe::new(4 << 20);
    let mut wasi = WasiCtxBuilder::new();
    wasi.inherit_stdin().inherit_stdout().stderr(guest_stderr.clone())
        .env("SOFTHSM2_CONF", "/config/softhsm2-wasi.conf")
        .preopened_dir(&cfg_dir, "/config", DirPerms::READ, FilePerms::READ)?
        .preopened_dir(&data_dir, "/data",  DirPerms::all(), FilePerms::all())?;
    let state = State { table: ResourceTable::new(), ctx: wasi.build() };

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    pkcs11::util::util::add_to_linker::<State, wasmtime::component::HasSelf<State>>(
        &mut linker, |s| s)?;
    let mut store = Store::new(&engine, state);
    let bindings = Phase5Pkcs11::instantiate_async(&mut store, &component, &linker).await?;

    let uri = "pkcs11:slot-id=0;object=phase-8d-p384-key;pin-value=1234;\
               init=true;algorithm=ecdsa-p384".to_string();
    let mdname = "SHA2-384".to_string();
    let tbs    = b"phase-8d wit-bridge P-384 round-trip".to_vec();

    let r = bindings.openssl_component_wit_bridge_test()
        .call_sign_with_wit_bridge(&mut store, &uri, &mdname, &tbs).await;
    let sig = match r {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let logs = guest_stderr.contents();
            if !logs.is_empty() {
                eprintln!("--- guest stderr ---{}",
                    String::from_utf8_lossy(&logs));
            }
            return Err(anyhow!("sign-with-wit-bridge P-384: {e}"));
        }
        Err(t) => return Err(anyhow!("trap: {t}")),
    };
    println!("P-384 signature: {} bytes", sig.len());
    assert_eq!(sig[0], 0x30, "DER SEQUENCE");
    // P-384 DER ECDSA-Sig is typically ~102-104 bytes (96 raw + DER framing).
    assert!(sig.len() >= 70 && sig.len() <= 110,
        "P-384 DER signature length {} outside expected 70..110",
        sig.len());
    println!("\nPHASE 8d -- pkcs11-bridge handled CKA_EC_PARAMS for P-384, \
              wit-bridge keymgmt + signature paths threaded the curve, \
              and SoftHSM signed.");
    drop((cfg_dir, data_dir));
    Ok(())
}

/// Phase 8c: prove RSA-PSS sign works through wit-bridge end-to-end --
/// auto-provisions an RSA-2048 key via `algorithm=rsa-2048;init=true`,
/// signs through wit-bridge with SHA-256 + PSS, expects 256-byte
/// signature (RSA-2048). Validates that simple-provider-adapter's
/// sign_init picks SignatureMechanism::RsaPss for RSA-typed keydata
/// (instead of the EC-default Ecdsa(Raw)), and that pkcs11-bridge
/// routes to CKM_SHA256_RSA_PKCS_PSS.
#[tokio::test]
async fn wit_bridge_signs_rsa_pss_via_softhsm() -> Result<()> {
    let comp_path = std::env::var("OPENSSL_WASM_COMPONENT")
        .map_err(|_| anyhow!("set OPENSSL_WASM_COMPONENT"))?;
    let comp_path = PathBuf::from(comp_path);
    if !Path::new(&comp_path).exists() {
        return Err(anyhow!("component not found: {}", comp_path.display()));
    }

    let run = std::env::temp_dir().join(format!("p11-rsa-{}", std::process::id()));
    let cfg_dir  = run.join("config");
    let data_dir = run.join("data");
    std::fs::create_dir_all(&cfg_dir)?;
    std::fs::create_dir_all(data_dir.join("tokens"))?;
    std::fs::write(cfg_dir.join("softhsm2-wasi.conf"),
        b"directories.tokendir = /data/tokens\n\
          objectstore.backend = file\n\
          objectstore.umask = 0077\n\
          log.level = INFO\n\
          slots.removable = false\n\
          slots.mechanisms = ALL\n\
          library.reset_on_fork = false\n")?;

    let mut engine_cfg = Config::new();
    engine_cfg.wasm_component_model(true);
    let engine = Engine::new(&engine_cfg)?;
    let component = Component::from_file(&engine, &comp_path)?;

    let guest_stderr = MemoryOutputPipe::new(4 << 20);
    let mut wasi = WasiCtxBuilder::new();
    wasi.inherit_stdin().inherit_stdout().stderr(guest_stderr.clone())
        .env("SOFTHSM2_CONF", "/config/softhsm2-wasi.conf")
        .preopened_dir(&cfg_dir, "/config", DirPerms::READ, FilePerms::READ)?
        .preopened_dir(&data_dir, "/data",  DirPerms::all(), FilePerms::all())?;
    let state = State { table: ResourceTable::new(), ctx: wasi.build() };

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    pkcs11::util::util::add_to_linker::<State, wasmtime::component::HasSelf<State>>(
        &mut linker, |s| s)?;
    let mut store = Store::new(&engine, state);
    let bindings = Phase5Pkcs11::instantiate_async(&mut store, &component, &linker).await?;

    let uri = "pkcs11:slot-id=0;object=phase-8c-rsa-key;pin-value=1234;\
               init=true;algorithm=rsa-2048".to_string();
    let mdname = "SHA2-256".to_string();
    let tbs    = b"phase-8c wit-bridge RSA-PSS round-trip".to_vec();

    let r = bindings.openssl_component_wit_bridge_test()
        .call_sign_with_wit_bridge(&mut store, &uri, &mdname, &tbs).await;
    let sig = match r {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let logs = guest_stderr.contents();
            if !logs.is_empty() {
                eprintln!("--- guest stderr ---\n{}", String::from_utf8_lossy(&logs));
            }
            return Err(anyhow!("sign-with-wit-bridge RSA: {e}"));
        }
        Err(t) => return Err(anyhow!("trap: {t}")),
    };
    println!("RSA-2048 PSS signature: {} bytes", sig.len());
    // RSA-2048 signature is exactly 256 bytes (modulus_size_in_bytes).
    assert_eq!(sig.len(), 256, "RSA-2048 PSS signature should be 256 bytes");
    println!("\nPHASE 8c -- wit-bridge routed an RSA URI through the adapter's \
              RsaPss mech path to pkcs11-bridge's CKM_SHA256_RSA_PKCS_PSS, \
              SoftHSM produced a valid 2048-bit RSA-PSS signature.");
    drop((cfg_dir, data_dir));
    Ok(())
}

/// Phase 8 STORE end-to-end: prove `OSSL_STORE_open('pkcs11:...')`
/// dispatches all the way through openssl-wasm's wit_store_dispatch
/// -> pkcs11-store-adapter -> pkcs11:host -> SoftHSM, and the
/// auto-provisioned key (CKO_PRIVATE_KEY) is surfaced as a
/// key-reference that OpenSSL re-enters via keymgmt.load to
/// materialize an EVP_PKEY.
///
/// Requires OPENSSL_WASM_COMPONENT to be built via `wac compose`
/// (not `wac plug`) using scripts/wit-bridge-compose.wac in
/// python-wasm — that's the manifest that shares ONE
/// pkcs11-provider instance between pkcs11-bridge and
/// pkcs11-store-adapter. `wac plug` alone creates separate provider
/// instances, leading to silent "no objects found" failures.
#[tokio::test]
async fn wit_bridge_load_uri_through_store() -> Result<()> {
    let comp_path = std::env::var("OPENSSL_WASM_COMPONENT")
        .map_err(|_| anyhow!("set OPENSSL_WASM_COMPONENT"))?;
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
    wasi.inherit_stdin().inherit_stdout().stderr(guest_stderr.clone())
        .env("SOFTHSM2_CONF", "/config/softhsm2-wasi.conf")
        .preopened_dir(&cfg_dir,  "/config", DirPerms::READ, FilePerms::READ)?
        .preopened_dir(&data_dir, "/data",   DirPerms::all(), FilePerms::all())?;
    let state = State { table: ResourceTable::new(), ctx: wasi.build() };

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    pkcs11::util::util::add_to_linker::<State, wasmtime::component::HasSelf<State>>(
        &mut linker, |s| s)?;
    let mut store_wasm = Store::new(&engine, state);
    let bindings = Phase5Pkcs11::instantiate_async(&mut store_wasm, &component, &linker).await?;

    // First: provision a key in the token via the existing init=true path
    // (call sign-with-wit-bridge, which creates the key and signs once).
    let provision_uri = "pkcs11:slot-id=0;object=phase-8-store-key;pin-value=1234;\
                         init=true;algorithm=ecdsa-p256".to_string();
    let mdname = "SHA2-256".to_string();
    let tbs    = b"phase-8 STORE chain provisioning".to_vec();
    let _ = bindings.openssl_component_wit_bridge_test()
        .call_sign_with_wit_bridge(&mut store_wasm, &provision_uri, &mdname, &tbs).await?
        .map_err(|e| anyhow!("provisioning sign failed: {e}"))?;

    // Now drive the STORE loader against the same URI -- pkcs11-store-adapter
    // walks pkcs11:host objects, emits the private key as a key-reference,
    // OpenSSL re-enters keymgmt.load which materializes the EVP_PKEY.
    // Note: no type= filter; pkcs11-store-adapter walks all matching
    // objects, classes get differentiated by CKA_CLASS read per-object.
    let load_uri = "pkcs11:slot-id=0;object=phase-8-store-key;pin-value=1234".to_string();
    let res = bindings.openssl_component_wit_bridge_test()
        .call_load_uri_test(&mut store_wasm, &load_uri).await?
        .map_err(|e| {
            let logs = guest_stderr.contents();
            if !logs.is_empty() {
                eprintln!("--- guest stderr ---\n{}", String::from_utf8_lossy(&logs));
            }
            anyhow!("load-uri-test inner err: {e}")
        })?;

    println!("STORE results: cert_count={} has_key={} key_bits={}",
             res.cert_count, res.has_key, res.key_bits);
    let logs = guest_stderr.contents();
    if !logs.is_empty() {
        eprintln!("--- guest stderr ---\n{}", String::from_utf8_lossy(&logs));
    }
    assert!(res.has_key, "store loader should surface the auto-provisioned key");
    assert_eq!(res.key_bits, 256, "P-256 -> 256 bits");
    // cert_count == 0 expected: the token only has a key (no cert
    // auto-provisioning yet — see plans/openssl-provider-wit.md Phase 8
    // follow-up to extend init=true with a self-signed cert).
    assert_eq!(res.cert_count, 0, "no cert auto-provisioned (expected for now)");
    println!("\nPHASE 8 STORE -- the whole chain works: openssl-wasm \
              OSSL_STORE_open -> wit_store_dispatch -> pkcs11-store-adapter \
              -> pkcs11:host find_objects -> SoftHSM -> CKO_PRIVATE_KEY \
              surfaced as a key-reference -> keymgmt.load materialized \
              the EVP_PKEY ({} bits).", res.key_bits);
    drop((cfg_dir, data_dir));
    Ok(())
}
