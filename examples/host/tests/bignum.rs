//! BIGNUM arithmetic.

use openssl_wasm_host::{Fixture};

#[tokio::test]
async fn mul_and_to_hex() {
    let mut f = Fixture::new().await.unwrap();
    let e = f.bindings.openssl_component_bignum().bn()
        .call_from_hex(&mut f.store, "10001").await.unwrap().unwrap();
    let sq = f.bindings.openssl_component_bignum().bn()
        .call_mul(&mut f.store, e, e).await.unwrap();
    let s = f.bindings.openssl_component_bignum().bn()
        .call_to_hex(&mut f.store, sq).await.unwrap();
    // OpenSSL pads BN_bn2hex to even digits.
    assert_eq!(s.to_uppercase().trim_start_matches('0'), "100020001");
}

#[tokio::test]
async fn mod_exp_rsa_like() {
    // 2^10 mod 1000 = 1024 mod 1000 = 24
    let mut f = Fixture::new().await.unwrap();
    let bn = f.bindings.openssl_component_bignum().bn();
    let base = bn.call_from_u64(&mut f.store, 2).await.unwrap();
    let exp = bn.call_from_u64(&mut f.store, 10).await.unwrap();
    let m = bn.call_from_u64(&mut f.store, 1000).await.unwrap();
    let got = bn.call_mod_exp(&mut f.store, base, exp, m).await.unwrap()
        .unwrap();
    let s = bn.call_to_dec(&mut f.store, got).await.unwrap();
    assert_eq!(s, "24");
}

#[tokio::test]
async fn prime_smoke() {
    // 2^31 - 1 = 2147483647 is prime.
    let mut f = Fixture::new().await.unwrap();
    let bn = f.bindings.openssl_component_bignum().bn();
    let p = bn.call_from_u64(&mut f.store, 2147483647).await.unwrap();
    assert!(bn.call_is_prime(&mut f.store, p).await.unwrap());
    let q = bn.call_from_u64(&mut f.store, 2147483649).await.unwrap();
    assert!(!bn.call_is_prime(&mut f.store, q).await.unwrap());
}
