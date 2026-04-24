//! Extended bignum coverage.

use openssl_wasm_host::Fixture;

#[tokio::test]
async fn mod_inverse_of_coprimes() {
    // 3^-1 mod 7 = 5 (since 3*5 = 15 ≡ 1 mod 7).
    let mut f = Fixture::new().await.unwrap();
    let bn = f.bindings.openssl_component_bignum().bn();
    let three = bn.call_from_u64(&mut f.store, 3).await.unwrap();
    let seven = bn.call_from_u64(&mut f.store, 7).await.unwrap();
    let inv = bn.call_mod_inverse(&mut f.store, three, seven).await.unwrap().unwrap();
    let s = bn.call_to_dec(&mut f.store, inv).await.unwrap();
    assert_eq!(s, "5");
}

#[tokio::test]
async fn mod_inverse_nonexistent_returns_error() {
    // gcd(2, 4) = 2 ≠ 1, so 2^-1 mod 4 doesn't exist.
    let mut f = Fixture::new().await.unwrap();
    let bn = f.bindings.openssl_component_bignum().bn();
    let two = bn.call_from_u64(&mut f.store, 2).await.unwrap();
    let four = bn.call_from_u64(&mut f.store, 4).await.unwrap();
    let r = bn.call_mod_inverse(&mut f.store, two, four).await.unwrap();
    assert!(r.is_err());
}

#[tokio::test]
async fn gcd_correct() {
    let mut f = Fixture::new().await.unwrap();
    let bn = f.bindings.openssl_component_bignum().bn();
    let a = bn.call_from_u64(&mut f.store, 252).await.unwrap();
    let b = bn.call_from_u64(&mut f.store, 105).await.unwrap();
    let g = bn.call_gcd(&mut f.store, a, b).await.unwrap();
    assert_eq!(bn.call_to_dec(&mut f.store, g).await.unwrap(), "21");
}

#[tokio::test]
async fn generate_prime_yields_prime() {
    let mut f = Fixture::new().await.unwrap();
    let bn = f.bindings.openssl_component_bignum().bn();
    let p = bn.call_generate_prime(&mut f.store, 32, false).await.unwrap().unwrap();
    assert!(bn.call_is_prime(&mut f.store, p).await.unwrap());
    assert_eq!(bn.call_bits(&mut f.store, p).await.unwrap(), 32);
}

#[tokio::test]
async fn random_below_in_range() {
    let mut f = Fixture::new().await.unwrap();
    let bn = f.bindings.openssl_component_bignum().bn();
    let upper = bn.call_from_u64(&mut f.store, 1_000_000).await.unwrap();
    for _ in 0..8 {
        let upper_c = bn.call_clone(&mut f.store, upper).await.unwrap();
        let r = bn.call_random_below(&mut f.store, upper_c).await.unwrap().unwrap();
        let s = bn.call_to_dec(&mut f.store, r).await.unwrap();
        let n: u64 = s.parse().unwrap();
        assert!(n < 1_000_000);
    }
}

#[tokio::test]
async fn from_dec_and_back() {
    let mut f = Fixture::new().await.unwrap();
    let bn = f.bindings.openssl_component_bignum().bn();
    let x = bn.call_from_dec(&mut f.store, "1234567890123456789012345")
        .await.unwrap().unwrap();
    assert_eq!(bn.call_to_dec(&mut f.store, x).await.unwrap(),
               "1234567890123456789012345");
}

#[tokio::test]
async fn to_be_bytes_with_padding() {
    let mut f = Fixture::new().await.unwrap();
    let bn = f.bindings.openssl_component_bignum().bn();
    let x = bn.call_from_u64(&mut f.store, 0x0102).await.unwrap();
    // No padding: 2 bytes.
    let x_c = bn.call_clone(&mut f.store, x).await.unwrap();
    let raw = bn.call_to_be_bytes(&mut f.store, x_c, None).await.unwrap();
    assert_eq!(raw, vec![0x01, 0x02]);
    // Pad to 8 bytes.
    let padded = bn.call_to_be_bytes(&mut f.store, x, Some(8)).await.unwrap();
    assert_eq!(padded, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02]);
}
