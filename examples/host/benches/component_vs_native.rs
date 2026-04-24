//! Component vs native OpenSSL baseline.
//!
//! Uses criterion's iter_custom so we can batch iterations under a
//! single async borrow of the store, sidestepping FnMut lifetime rules.
//!
//! Run with `cargo bench --bench component_vs_native`.

use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main, Throughput};
use openssl_wasm_host::{Fixture, exports};

use exports::openssl::component::cipher as ciph;
use exports::openssl::component::digest::Algorithm;
use exports::openssl::component::pkey as pk;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all().build().unwrap()
}

fn bench_digest_sha256(c: &mut Criterion) {
    let rt = rt();
    let mut group = c.benchmark_group("sha256");
    for size in [1024usize, 65_536, 1_048_576] {
        let data = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("component", size), &data, |b, data| {
            b.iter_custom(|iters| {
                rt.block_on(async {
                    let mut f = Fixture::new().await.unwrap();
                    let start = Instant::now();
                    for _ in 0..iters {
                        let _ = f.bindings.openssl_component_digest()
                            .call_one_shot(&mut f.store, Algorithm::Sha256, data)
                            .await.unwrap().unwrap();
                    }
                    start.elapsed()
                })
            });
        });

        group.bench_with_input(BenchmarkId::new("native", size), &data, |b, data| {
            b.iter(|| {
                openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data).unwrap()
            });
        });
    }
    group.finish();
}

fn bench_aes_256_gcm_seal(c: &mut Criterion) {
    let rt = rt();
    let key = vec![0x42u8; 32];
    let nonce = vec![0x24u8; 12];
    let aad: Vec<u8> = vec![];

    let mut group = c.benchmark_group("aes-256-gcm-seal");
    for size in [1024usize, 65_536] {
        let data = vec![0x77u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("component", size), &data, |b, data| {
            b.iter_custom(|iters| {
                rt.block_on(async {
                    let mut f = Fixture::new().await.unwrap();
                    let start = Instant::now();
                    for _ in 0..iters {
                        let _ = f.bindings.openssl_component_cipher()
                            .call_seal(&mut f.store, ciph::Algorithm::Aes256Gcm,
                                       &key, &nonce, &aad, data, 16)
                            .await.unwrap().unwrap();
                    }
                    start.elapsed()
                })
            });
        });

        group.bench_with_input(BenchmarkId::new("native", size), &data, |b, data| {
            b.iter(|| {
                let mut tag = [0u8; 16];
                openssl::symm::encrypt_aead(
                    openssl::symm::Cipher::aes_256_gcm(),
                    &key, Some(&nonce), &aad, data, &mut tag).unwrap()
            });
        });
    }
    group.finish();
}

fn bench_ed25519_sign(c: &mut Criterion) {
    let rt = rt();
    let msg = vec![0xabu8; 1024];
    let native_key = openssl::pkey::PKey::generate_ed25519().unwrap();

    let mut group = c.benchmark_group("ed25519-sign");
    group.bench_function("component", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let mut f = Fixture::new().await.unwrap();
                let key = f.bindings.openssl_component_pkey().pkey()
                    .call_generate(&mut f.store,
                        pk::KeygenParams::Ed(pk::EdwardsCurve::Ed25519))
                    .await.unwrap().unwrap();
                let start = Instant::now();
                for _ in 0..iters {
                    let _ = f.bindings.openssl_component_pkey().pkey()
                        .call_sign_message(&mut f.store, key, None, &msg, None)
                        .await.unwrap().unwrap();
                }
                start.elapsed()
            })
        });
    });
    group.bench_function("native", |b| {
        b.iter(|| {
            let mut signer = openssl::sign::Signer::new_without_digest(&native_key).unwrap();
            signer.sign_oneshot_to_vec(&msg).unwrap()
        });
    });
    group.finish();
}

fn configure() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(3))
}

criterion_group!{
    name = benches;
    config = configure();
    targets = bench_digest_sha256, bench_aes_256_gcm_seal, bench_ed25519_sign
}
criterion_main!(benches);
