//! Random — basic sanity tests.

use openssl_wasm_host::Fixture;

#[tokio::test]
async fn bytes_length_matches() {
    let mut f = Fixture::new().await.unwrap();
    for n in [0u32, 1, 16, 64, 1024] {
        let b = f.bindings.openssl_component_random()
            .call_bytes(&mut f.store, n).await.unwrap().unwrap();
        assert_eq!(b.len(), n as usize);
    }
}

#[tokio::test]
async fn bytes_distinct() {
    let mut f = Fixture::new().await.unwrap();
    let a = f.bindings.openssl_component_random()
        .call_bytes(&mut f.store, 32).await.unwrap().unwrap();
    let b = f.bindings.openssl_component_random()
        .call_bytes(&mut f.store, 32).await.unwrap().unwrap();
    assert_ne!(a, b, "two 32-byte draws must not collide");
}
