//! Known-answer tests for digest.
//!
//! Vectors from FIPS 180-4 and RFC 6234 where possible.

use openssl_wasm_host::{Fixture, exports, hex};
use exports::openssl::component::digest::Algorithm;

macro_rules! digest_vector {
    ($name:ident, $alg:expr, $input:expr, $expected:literal) => {
        #[tokio::test]
        async fn $name() {
            let mut f = Fixture::new().await.unwrap();
            let out = f.bindings.openssl_component_digest()
                .call_one_shot(&mut f.store, $alg, &$input.to_vec())
                .await.unwrap().unwrap();
            assert_eq!(hex(&out), $expected);
        }
    };
}

// SHA-256("") — FIPS 180-4 empty-string vector.
digest_vector!(sha256_empty, Algorithm::Sha256, b"",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

digest_vector!(sha256_abc, Algorithm::Sha256, b"abc",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

digest_vector!(sha1_abc, Algorithm::Sha1, b"abc",
    "a9993e364706816aba3e25717850c26c9cd0d89d");

digest_vector!(sha512_abc, Algorithm::Sha512, b"abc",
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

digest_vector!(sha3_256_empty, Algorithm::Sha3t256, b"",
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

#[tokio::test]
async fn shake128_xof_empty() {
    // SHAKE128("" , 32 bytes) — NIST vector.
    let mut f = Fixture::new().await.unwrap();
    let out = f.bindings.openssl_component_digest()
        .call_one_shot_xof(&mut f.store, Algorithm::Shake128, &vec![], 32)
        .await.unwrap().unwrap();
    assert_eq!(hex(&out),
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
}

#[tokio::test]
async fn streaming_matches_one_shot() {
    let mut f = Fixture::new().await.unwrap();
    let msg = b"the quick brown fox jumps over the lazy dog".repeat(50);

    let one_shot = f.bindings.openssl_component_digest()
        .call_one_shot(&mut f.store, Algorithm::Sha256, &msg)
        .await.unwrap().unwrap();

    let ctx = f.bindings.openssl_component_digest().context()
        .call_constructor(&mut f.store, Algorithm::Sha256).await.unwrap();
    let (a, b) = msg.split_at(msg.len() / 3);
    f.bindings.openssl_component_digest().context()
        .call_update(&mut f.store, ctx, &a.to_vec()).await.unwrap().unwrap();
    f.bindings.openssl_component_digest().context()
        .call_update(&mut f.store, ctx, &b.to_vec()).await.unwrap().unwrap();
    let streamed = f.bindings.openssl_component_digest().context()
        .call_finish(&mut f.store, ctx).await.unwrap().unwrap();

    assert_eq!(one_shot, streamed);
}
