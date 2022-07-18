use pairing_crypto::bbs::ciphersuites::bls12_381::{
    sign,
    verify,
    BbsSignRequest,
    BbsVerifyRequest,
    KeyPair,
};
use rand::{rngs::OsRng, RngCore};
use std::time::Duration;

#[macro_use]
extern crate criterion;

use criterion::{black_box, Criterion};

const TEST_KEY_INFOS: &[u8; 50] =
    b"12345678901234567890123456789012345678901234567890";

const TEST_HEADER: &[u8; 16] = b"some_app_context";

fn sign_benchmark(c: &mut Criterion) {
    let header = TEST_HEADER.as_ref();
    let (secret_key, public_key) =
        KeyPair::random(&mut OsRng, TEST_KEY_INFOS.as_ref())
            .map(|key_pair| {
                (
                    key_pair.secret_key.to_bytes(),
                    key_pair.public_key.to_octets(),
                )
            })
            .expect("key generation failed");

    for num_messages in vec![1, 10, 100, 1000] {
        // generating random 100 bytes messages
        let mut messages = vec![[0u8; 100]; num_messages];
        for m in messages.iter_mut() {
            rand::thread_rng().fill_bytes(m);
        }
        let messages: Vec<&[u8]> =
            messages.iter().map(|m| m.as_ref()).collect();

        c.bench_function(
            &format!("sign - total messages {}", num_messages),
            |b| {
                b.iter(|| {
                    sign(BbsSignRequest {
                        secret_key: black_box(&secret_key),
                        public_key: black_box(&public_key),
                        header: black_box(Some(header)),
                        messages: black_box(Some(&messages[..])),
                    })
                    .unwrap();
                });
            },
        );

        let signature = sign(BbsSignRequest {
            secret_key: &secret_key,
            public_key: &public_key,
            header: Some(header),
            messages: Some(&messages[..]),
        })
        .expect("signature generation failed");

        c.bench_function(
            &format!("sign_verify - total messages {}", num_messages),
            |b| {
                b.iter(|| {
                    assert!(verify(BbsVerifyRequest {
                        public_key: black_box(&public_key),
                        header: black_box(Some(header)),
                        messages: black_box(Some(&messages[..])),
                        signature: black_box(&signature),
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
