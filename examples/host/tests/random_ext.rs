//! Extended random coverage.

use openssl_wasm_host::Fixture;

#[tokio::test]
async fn private_bytes_is_not_identical_to_public() {
    // Not a statistical test — just checks the two DRBGs are independent
    // handles (they may share state but not produce identical streams).
    let mut f = Fixture::new().await.unwrap();
    let a = f.bindings.openssl_component_random()
        .call_bytes(&mut f.store, 32).await.unwrap().unwrap();
    let b = f.bindings.openssl_component_random()
        .call_private_bytes(&mut f.store, 32).await.unwrap().unwrap();
    assert_ne!(a, b);
}

#[tokio::test]
async fn add_seed_is_noop_and_safe() {
    let mut f = Fixture::new().await.unwrap();
    let material = vec![0x42u8; 64];
    f.bindings.openssl_component_random()
        .call_add_seed(&mut f.store, &material, 128.0).await.unwrap();
    // Subsequent draws still work.
    let b = f.bindings.openssl_component_random()
        .call_bytes(&mut f.store, 16).await.unwrap().unwrap();
    assert_eq!(b.len(), 16);
}
