#![no_main]

use std::sync::{Mutex, OnceLock};
use libfuzzer_sys::fuzz_target;
use openssl_wasm_host::{Fixture, exports};
use tokio::runtime::Runtime;
use exports::openssl::component::x509 as x;

static STATE: OnceLock<Mutex<State>> = OnceLock::new();
struct State { rt: Runtime, fixture: Fixture }

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let fixture = rt.block_on(Fixture::new()).expect("component load");
        Mutex::new(State { rt, fixture })
    })
}

fuzz_target!(|data: &[u8]| {
    let mut g = state().lock().unwrap();
    let State { rt, fixture } = &mut *g;
    rt.block_on(async {
        let _ = fixture.bindings.openssl_component_x509().crl()
            .call_parse(&mut fixture.store, data, x::Encoding::Der).await.ok();
        let _ = fixture.bindings.openssl_component_error()
            .call_clear_errors(&mut fixture.store).await.ok();
    });
});
