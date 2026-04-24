//! libFuzzer target: feed arbitrary bytes to x509::certificate::parse.
//!
//! The fixture + tokio runtime are held in a OnceLock so each
//! iteration reuses them. Individual parse calls are submillisecond
//! once the component is loaded.

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
}

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        let fixture = rt.block_on(Fixture::new()).expect("failed to load component");
        Mutex::new(State { rt, fixture })
    })
}

fuzz_target!(|data: &[u8]| {
    let mut guard = state().lock().unwrap();
    let State { rt, fixture } = &mut *guard;
    rt.block_on(async {
        // DER decode.
        let _ = fixture.bindings.openssl_component_x509().certificate()
            .call_parse(&mut fixture.store, data, x::Encoding::Der)
            .await.ok();
        // PEM decode on the same input.
        let _ = fixture.bindings.openssl_component_x509().certificate()
            .call_parse(&mut fixture.store, data, x::Encoding::Pem)
            .await.ok();
        // Clear queued errors so future iterations start fresh.
        let _ = fixture.bindings.openssl_component_error()
            .call_clear_errors(&mut fixture.store).await.ok();
    });
});
