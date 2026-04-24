//! Extended digest coverage for remaining algorithms.

use openssl_wasm_host::{Fixture, exports, hex};
use exports::openssl::component::digest::Algorithm;

#[tokio::test]
async fn sha224_fips_vector() {
    // SHA-224("abc") — FIPS 180-4.
    let mut f = Fixture::new().await.unwrap();
    let out = f.bindings.openssl_component_digest()
        .call_one_shot(&mut f.store, Algorithm::Sha224, &b"abc".to_vec())
        .await.unwrap().unwrap();
    assert_eq!(hex(&out),
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
}

#[tokio::test]
async fn sha384_fips_vector() {
    let mut f = Fixture::new().await.unwrap();
    let out = f.bindings.openssl_component_digest()
        .call_one_shot(&mut f.store, Algorithm::Sha384, &b"abc".to_vec())
        .await.unwrap().unwrap();
    assert_eq!(hex(&out),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
}

#[tokio::test]
async fn ripemd160_vector() {
    // RIPEMD-160("abc") — original spec vector.
    let mut f = Fixture::new().await.unwrap();
    let out = f.bindings.openssl_component_digest()
        .call_one_shot(&mut f.store, Algorithm::Ripemd160, &b"abc".to_vec())
        .await.unwrap().unwrap();
    assert_eq!(hex(&out), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
}

#[tokio::test]
async fn sm3_vector() {
    // SM3("abc") — GM/T 0004-2012.
    let mut f = Fixture::new().await.unwrap();
    let out = f.bindings.openssl_component_digest()
        .call_one_shot(&mut f.store, Algorithm::Sm3, &b"abc".to_vec())
        .await.unwrap().unwrap();
    assert_eq!(hex(&out),
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
}

#[tokio::test]
async fn md5_vector() {
    let mut f = Fixture::new().await.unwrap();
    let out = f.bindings.openssl_component_digest()
        .call_one_shot(&mut f.store, Algorithm::Md5, &b"abc".to_vec())
        .await.unwrap().unwrap();
    assert_eq!(hex(&out), "900150983cd24fb0d6963f7d28e17f72");
}

#[tokio::test]
async fn blake2b_512_empty() {
    let mut f = Fixture::new().await.unwrap();
    let out = f.bindings.openssl_component_digest()
        .call_one_shot(&mut f.store, Algorithm::Blake2b512, &vec![])
        .await.unwrap().unwrap();
    // Known BLAKE2b-512 of empty input.
    assert_eq!(hex(&out),
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
}

#[tokio::test]
async fn context_clone_preserves_mid_stream_state() {
    // Fingerprint an X.509-like use case: update with prefix, clone,
    // continue both branches with different suffixes, assert different outputs.
    let mut f = Fixture::new().await.unwrap();
    let ctx = f.bindings.openssl_component_digest().context()
        .call_constructor(&mut f.store, Algorithm::Sha256).await.unwrap();
    f.bindings.openssl_component_digest().context()
        .call_update(&mut f.store, ctx, &b"shared prefix".to_vec())
        .await.unwrap().unwrap();

    let ctx2 = f.bindings.openssl_component_digest().context()
        .call_clone(&mut f.store, ctx).await.unwrap();
    f.bindings.openssl_component_digest().context()
        .call_update(&mut f.store, ctx, &b" A".to_vec()).await.unwrap().unwrap();
    f.bindings.openssl_component_digest().context()
        .call_update(&mut f.store, ctx2, &b" B".to_vec()).await.unwrap().unwrap();

    let a = f.bindings.openssl_component_digest().context()
        .call_finish(&mut f.store, ctx).await.unwrap().unwrap();
    let b = f.bindings.openssl_component_digest().context()
        .call_finish(&mut f.store, ctx2).await.unwrap().unwrap();
    assert_ne!(a, b);

    // Compare against one-shot equivalents.
    let one_shot_a = f.bindings.openssl_component_digest()
        .call_one_shot(&mut f.store, Algorithm::Sha256, &b"shared prefix A".to_vec())
        .await.unwrap().unwrap();
    let one_shot_b = f.bindings.openssl_component_digest()
        .call_one_shot(&mut f.store, Algorithm::Sha256, &b"shared prefix B".to_vec())
        .await.unwrap().unwrap();
    assert_eq!(a, one_shot_a);
    assert_eq!(b, one_shot_b);
}
