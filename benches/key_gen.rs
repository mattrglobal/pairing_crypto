use std::time::Duration;

use pairing_crypto::bbs::ciphersuites::bls12_381::{PublicKey, SecretKey};

#[macro_use]
extern crate criterion;

use criterion::{black_box, Criterion};
use rand::rngs::OsRng;

fn secret_key_gen_from_seed_benchmark(c: &mut Criterion) {
    const KEY_GEN_SEED: &[u8; 32] = b"not_A_random_seed_at_Allllllllll";

    const TEST_KEY_INFOS: &[u8; 50] =
        b"12345678901234567890123456789012345678901234567890";

    c.bench_function(&format!("secret key_gen from seed"), |b| {
        b.iter(|| {
            SecretKey::new(
                black_box(KEY_GEN_SEED.as_ref()),
                black_box(TEST_KEY_INFOS.as_ref()),
            )
            .unwrap();
        });
    });
}

fn secret_key_gen_from_random_benchmark(c: &mut Criterion) {
    c.bench_function(&format!("secret key_gen from random"), |b| {
        b.iter(|| {
            SecretKey::random(black_box(&mut OsRng)).unwrap();
        });
    });
}

fn sk_to_pk_benchmark(c: &mut Criterion) {
    let sk =
        SecretKey::random(&mut OsRng).expect("secret key generation failed");

    c.bench_function(&format!("sk_to_pk from random"), |b| {
        b.iter(|| {
            let _ = PublicKey::from(black_box(&sk));
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets = secret_key_gen_from_seed_benchmark, secret_key_gen_from_random_benchmark, sk_to_pk_benchmark
);
criterion_main!(benches);
