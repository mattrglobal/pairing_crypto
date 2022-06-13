use std::time::Duration;

use pairing_crypto::bbs::ciphersuites::bls12_381::{
    Generators,
    Message,
    PublicKey,
    SecretKey,
    Signature,
    GLOBAL_BLIND_VALUE_GENERATOR_SEED,
    GLOBAL_MESSAGE_GENERATOR_SEED,
    GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
};

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rand::rngs::OsRng;

const HEADER: &[u8; 16] = b"some_app_context";

fn sign_benchmark(c: &mut Criterion) {
    let sk =
        SecretKey::random(&mut OsRng).expect("secret key generation failed");
    let pk = PublicKey::from(&sk);

    for num_messages in vec![1, 10, 100, 1000] {
        let gens = Generators::new(
            GLOBAL_BLIND_VALUE_GENERATOR_SEED,
            GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
            GLOBAL_MESSAGE_GENERATOR_SEED,
            num_messages,
        )
        .expect("generators creation failed");

        let messages: Vec<Message> = (0..num_messages)
            .map(|_| Message::random(&mut OsRng))
            .collect();

        c.bench_function(
            &format!("sign - total messages {}", num_messages),
            |b| {
                b.iter(|| {
                    let _ = Signature::new(
                        &sk,
                        &pk,
                        Some(&HEADER),
                        &gens,
                        &messages,
                    )
                    .unwrap();
                });
            },
        );

        let signature =
            Signature::new(&sk, &pk, Some(&HEADER), &gens, &messages).unwrap();
        c.bench_function(
            &format!("sign_verify - total messages {}", num_messages),
            |b| {
                b.iter(|| {
                    let _ = signature
                        .verify(&pk, Some(&HEADER), &gens, &messages)
                        .unwrap();
                });
            },
        );
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(20));
    targets = sign_benchmark
);
criterion_main!(benches);
