use std::time::Duration;

use pairing_crypto::bbs::ciphersuites::bls12_381::{
    Generators,
    GLOBAL_BLIND_VALUE_GENERATOR_SEED,
    GLOBAL_MESSAGE_GENERATOR_SEED,
    GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
};

#[macro_use]
extern crate criterion;

use criterion::Criterion;

fn generators_benchmark(c: &mut Criterion) {
    for num_generators in vec![1, 10, 100, 1000] {
        c.bench_function(
            &format!("generators - total numbers {}", num_generators),
            |b| {
                b.iter(|| {
                    let _ = Generators::new(
                        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
                        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
                        GLOBAL_MESSAGE_GENERATOR_SEED,
                        num_generators,
                    )
                    .expect("generators creation failed");
                });
            },
        );
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets = generators_benchmark
);
criterion_main!(benches);
