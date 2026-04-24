//! Extended MAC coverage (Poly1305, SipHash, KMAC, GMAC).

use openssl_wasm_host::{Fixture, exports, hex};
use exports::openssl::component::digest::Algorithm;
use exports::openssl::component::mac::{self, BlockCipher, GmacParams, HmacParams, KmacParams, Params};

fn hx(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn poly1305_rfc8439_test_vector() {
    // RFC 8439 §2.5.2. Poly1305 key + message → tag.
    let mut f = Fixture::new().await.unwrap();
    let key = hx("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let msg = b"Cryptographic Forum Research Group".to_vec();
    let tag = f.bindings.openssl_component_mac()
        .call_one_shot(&mut f.store, mac::Algorithm::Poly1305,
                       &key, &msg, &Params::Poly1305)
        .await.unwrap().unwrap();
    assert_eq!(hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
}

#[tokio::test]
async fn kmac256_smoke() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x40u8; 32];
    let msg = b"hello".to_vec();
    let tag1 = f.bindings.openssl_component_mac()
        .call_one_shot(&mut f.store, mac::Algorithm::Kmac256,
                       &key, &msg,
                       &Params::Kmac(KmacParams {
                           customization: None,
                           output_len: 64,
                       }))
        .await.unwrap().unwrap();
    assert_eq!(tag1.len(), 64);

    // Different output length gives different output.
    let tag2 = f.bindings.openssl_component_mac()
        .call_one_shot(&mut f.store, mac::Algorithm::Kmac256,
                       &key, &msg,
                       &Params::Kmac(KmacParams {
                           customization: None,
                           output_len: 32,
                       }))
        .await.unwrap().unwrap();
    assert_eq!(tag2.len(), 32);
    assert_ne!(&tag1[..32], &tag2[..],
               "different KMAC output lengths should produce different prefixes");
}

#[tokio::test]
async fn gmac_determinism() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x42u8; 32];
    let msg = b"ghash me".to_vec();
    let nonce = vec![0x24u8; 12];
    let a = f.bindings.openssl_component_mac()
        .call_one_shot(&mut f.store, mac::Algorithm::Gmac,
                       &key, &msg,
                       &Params::Gmac(GmacParams {
                           cipher: BlockCipher::Aes256,
                           nonce: nonce.clone(),
                       }))
        .await.unwrap().unwrap();
    let b = f.bindings.openssl_component_mac()
        .call_one_shot(&mut f.store, mac::Algorithm::Gmac,
                       &key, &msg,
                       &Params::Gmac(GmacParams {
                           cipher: BlockCipher::Aes256, nonce,
                       }))
        .await.unwrap().unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 16);
}

#[tokio::test]
async fn mac_streaming_matches_one_shot() {
    let mut f = Fixture::new().await.unwrap();
    let key = vec![0x0bu8; 20];
    let msg = b"streamed mac input".repeat(10);

    let one_shot = f.bindings.openssl_component_mac()
        .call_one_shot(&mut f.store, mac::Algorithm::Hmac,
                       &key, &msg,
                       &Params::Hmac(HmacParams { hash: Algorithm::Sha256 }))
        .await.unwrap().unwrap();

    let ctx = f.bindings.openssl_component_mac().context()
        .call_constructor(&mut f.store, mac::Algorithm::Hmac, &key,
                          &Params::Hmac(HmacParams { hash: Algorithm::Sha256 }))
        .await.unwrap();
    let (a, b) = msg.split_at(msg.len() / 2);
    f.bindings.openssl_component_mac().context()
        .call_update(&mut f.store, ctx, &a.to_vec()).await.unwrap().unwrap();
    f.bindings.openssl_component_mac().context()
        .call_update(&mut f.store, ctx, &b.to_vec()).await.unwrap().unwrap();
    let streamed = f.bindings.openssl_component_mac().context()
        .call_finish(&mut f.store, ctx).await.unwrap().unwrap();

    assert_eq!(one_shot, streamed);
}
