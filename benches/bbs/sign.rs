use pairing_crypto::bbs::ciphersuites::bls12_381::{
    sign,
    verify,
    BbsSignRequest,
    BbsVerifyRequest,
    KeyPair,
};
use rand::{rngs::OsRng, Rng};
use std::time::Duration;

#[macro_use]
extern crate criterion;

use criterion::{black_box, Criterion};

const TEST_KEY_INFOS: &[u8; 50] =
    b"12345678901234567890123456789012345678901234567890";

const TEST_HEADER: &[u8; 16] = b"some_app_context";

fn sign_benchmark(c: &mut Criterion) {
    let (secret_key, public_key) =
        KeyPair::random(&mut OsRng, TEST_KEY_INFOS.as_ref())
            .map(|key_pair| {
                (
                    key_pair.secret_key.to_bytes().to_vec(),
                    key_pair.public_key.point_to_octets().to_vec(),
                )
            })
            .expect("key generation failed");

    for num_messages in vec![1, 10, 100, 1000] {
        // generating random 32 bytes messages
        let messages: Vec<Vec<u8>> = (0..num_messages)
            .map(|_| rand::thread_rng().gen::<[u8; 32]>().to_vec())
            .collect();

        c.bench_function(
            &format!("sign - total messages {}", num_messages),
            |b| {
                b.iter(|| {
                    sign(BbsSignRequest {
                        secret_key: black_box(secret_key.clone()),
                        public_key: black_box(public_key.clone()),
                        header: black_box(Some(TEST_HEADER.as_ref().to_vec())),
                        messages: black_box(Some(messages.to_vec())),
                    })
                    .unwrap();
                });
            },
        );

        let signature = sign(BbsSignRequest {
            secret_key: secret_key.clone(),
            public_key: public_key.clone(),
            header: Some(TEST_HEADER.as_ref().to_vec()),
            messages: Some(messages.to_vec()),
        })
        .expect("signature generation failed");

        c.bench_function(
            &format!("sign_verify - total messages {}", num_messages),
            |b| {
                b.iter(|| {
                    assert!(verify(BbsVerifyRequest {
                        public_key: black_box(public_key.clone()),
                        header: black_box(Some(TEST_HEADER.as_ref().to_vec())),
                        messages: black_box(Some(messages.to_vec())),
                        signature: black_box(signature.to_vec()),
                    })
                    .unwrap());
                });
            },
        );
    }
}

criterion_group!(
    name = bbs_sign_benches;
    config = Criterion::default().measurement_time(Duration::from_secs(20));
    targets = sign_benchmark
);
criterion_main!(bbs_sign_benches);
