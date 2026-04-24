#![no_main]

use std::sync::{Mutex, OnceLock};
use libfuzzer_sys::fuzz_target;
use openssl_wasm_host::{Fixture, exports};
use tokio::runtime::Runtime;
use exports::openssl::component::x509 as x;

static STATE: OnceLock<Mutex<State>> = OnceLock::new();
struct State {
    rt: Runtime,
    fixture: Fixture,
    store_handle: wasmtime::component::ResourceAny,
}

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let mut fixture = rt.block_on(Fixture::new()).expect("component load");
        let store_handle = rt.block_on(async {
            fixture.bindings.openssl_component_x509().store()
                .call_constructor(&mut fixture.store).await.unwrap()
        });
        Mutex::new(State { rt, fixture, store_handle })
    })
}

fuzz_target!(|data: &[u8]| {
    let mut g = state().lock().unwrap();
    let State { rt, fixture, store_handle } = &mut *g;
    rt.block_on(async {
        let _ = fixture.bindings.openssl_component_x509()
            .call_cms_verify(&mut fixture.store, data, *store_handle,
                             None, x::Encoding::Der).await.ok();
        let _ = fixture.bindings.openssl_component_error()
            .call_clear_errors(&mut fixture.store).await.ok();
    });
});
