//! Shared test harness: instantiate the openssl component under wasmtime
//! and hand back typed bindings. All tests use `Fixture::new()`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

wasmtime::component::bindgen!({
    world: "openssl",
    path: "../../wit",
    imports: { default: async },
    exports: { default: async },
});

pub struct Host {
    pub wasi: WasiCtx,
    pub table: ResourceTable,
}

impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

pub struct Fixture {
    pub store: Store<Host>,
    pub bindings: Openssl,
}

impl Fixture {
    /// Build a store + instantiated component against the default
    /// component path (`$OPENSSL_WASM_COMPONENT` or
    /// `../../build/openssl-component.wasm`), with no network access.
    pub async fn new() -> Result<Self> {
        let mut b = WasiCtxBuilder::new();
        b.inherit_stdio();
        Self::with_builder(b).await
    }

    /// Build with a custom WasiCtxBuilder (e.g. to enable networking).
    pub async fn with_builder(mut builder: WasiCtxBuilder) -> Result<Self> {
        let path = Self::component_path();
        let engine = Engine::default();
        let component = Component::from_file(&engine, &path)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("loading {}", path.display()))?;
        let mut linker = Linker::<Host>::new(&engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

        let wasi = builder.build();
        let mut store = Store::new(&engine,
            Host { wasi, table: ResourceTable::new() });
        let bindings = Openssl::instantiate_async(&mut store, &component, &linker).await?;
        Ok(Self { store, bindings })
    }

    fn component_path() -> PathBuf {
        if let Some(p) = std::env::var_os("OPENSSL_WASM_COMPONENT") {
            return PathBuf::from(p);
        }
        // Fall back to the repo-relative path; works when cargo runs with
        // CWD = examples/host/.
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        here.join("../../build/openssl-component.wasm")
    }
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}
