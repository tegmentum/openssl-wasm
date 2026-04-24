//! Error-queue interface coverage.

use openssl_wasm_host::{Fixture, exports};

#[tokio::test]
async fn pop_empty_returns_none() {
    let mut f = Fixture::new().await.unwrap();
    // Ensure queue is clean (nothing before us has errored).
    f.bindings.openssl_component_error()
        .call_clear_errors(&mut f.store).await.unwrap();
    let r = f.bindings.openssl_component_error()
        .call_pop_error(&mut f.store).await.unwrap();
    assert!(r.is_none());
}

#[tokio::test]
async fn drain_after_forced_failure_yields_errors() {
    let mut f = Fixture::new().await.unwrap();
    f.bindings.openssl_component_error()
        .call_clear_errors(&mut f.store).await.unwrap();

    // Force an x509 parse failure to populate the queue.
    let bogus = b"not a certificate".to_vec();
    let _ = f.bindings.openssl_component_x509().certificate()
        .call_parse(&mut f.store, &bogus,
                    exports::openssl::component::x509::Encoding::Der)
        .await.unwrap();

    let errs = f.bindings.openssl_component_error()
        .call_drain_errors(&mut f.store).await.unwrap();
    assert!(!errs.is_empty(), "drain after forced failure should yield at least one error");
}

#[tokio::test]
async fn describe_returns_nonempty_string_for_nonzero_code() {
    let mut f = Fixture::new().await.unwrap();
    f.bindings.openssl_component_error()
        .call_clear_errors(&mut f.store).await.unwrap();
    let bogus = b"definitely not der".to_vec();
    let _ = f.bindings.openssl_component_x509().certificate()
        .call_parse(&mut f.store, &bogus,
                    exports::openssl::component::x509::Encoding::Der)
        .await.unwrap();
    let maybe = f.bindings.openssl_component_error()
        .call_pop_error(&mut f.store).await.unwrap();
    let info = maybe.expect("expected an error");
    let desc = f.bindings.openssl_component_error()
        .call_describe(&mut f.store, info.code).await.unwrap();
    assert!(!desc.is_empty());
}
