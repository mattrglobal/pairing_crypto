use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::KeyPair,
        bls12_381_g1_sha_256::{
            proof_gen as bls12_381_sha_256_proof_gen,
            proof_verify as bls12_381_sha_256_proof_verify,
            sign as bls12_381_sha_256_sign,
            verify as bls12_381_sha_256_verify,
        },
        bls12_381_g1_shake_256::{
            proof_gen as bls12_381_shake_256_proof_gen,
            proof_verify as bls12_381_shake_256_proof_verify,
            sign as bls12_381_shake_256_sign,
            verify as bls12_381_shake_256_verify,
        },
    },
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
};
use rand::{rngs::OsRng, RngCore};
use std::time::Duration;

#[macro_use]
extern crate criterion;

use criterion::{black_box, BenchmarkId, Criterion};

const TEST_KEY_INFOS: &[u8; 50] =
    b"12345678901234567890123456789012345678901234567890";

const TEST_HEADER: &[u8; 16] = b"some_app_context";
const TEST_PRESENTATION_HEADER: &[u8; 24] = b"test-presentation-header";

fn get_random_key_pair() -> ([u8; 32], [u8; 96]) {
    KeyPair::random(&mut OsRng, Some(TEST_KEY_INFOS))
        .map(|key_pair| {
            (
                key_pair.secret_key.to_bytes(),
                key_pair.public_key.to_octets(),
            )
        })
        .expect("key generation failed")
}

macro_rules! sign_benchmark_generator {
    ($benchmark_fn:ident, $ciphersuite:literal, $sign_fn:ident) => {
        fn $benchmark_fn(c: &mut Criterion) {
            let mut group = c.benchmark_group("BBS-Sign");
            let header = TEST_HEADER.as_ref();
            let (secret_key, public_key) = get_random_key_pair();

            for num_messages in vec![1, 10, 100, 1000] {
                // generating random 100 bytes messages
                let mut messages = vec![[0u8; 100]; num_messages];
                for m in messages.iter_mut() {
                    rand::thread_rng().fill_bytes(m);
                }
                let messages: Vec<&[u8]> =
                    messages.iter().map(|m| m.as_ref()).collect();

                group.bench_with_input(
                    BenchmarkId::new($ciphersuite, num_messages),
                    &num_messages,
                    |b, &_num_messages| {
                        b.iter(|| {
                            $sign_fn(&BbsSignRequest {
                                secret_key: black_box(&secret_key),
                                public_key: black_box(&public_key),
                                header: black_box(Some(header)),
                                messages: black_box(Some(&messages[..])),
                            })
                            .unwrap();
                        });
                    },
                );
            }
            group.finish();
        }
    };
}

macro_rules! verify_benchmark_generator {
    ($benchmark_fn:ident, $ciphersuite:literal, $sign_fn:ident, $verify_fn:ident) => {
        fn $benchmark_fn(c: &mut Criterion) {
            let header = TEST_HEADER.as_ref();
            let (secret_key, public_key) = get_random_key_pair();

            let mut group = c.benchmark_group("BBS-Verify");
            for num_messages in vec![1, 10, 100, 1000] {
                // generating random 100 bytes messages
                let mut messages = vec![[0u8; 100]; num_messages];
                for m in messages.iter_mut() {
                    rand::thread_rng().fill_bytes(m);
                }
                let messages: Vec<&[u8]> =
                    messages.iter().map(|m| m.as_ref()).collect();

                let signature = $sign_fn(&BbsSignRequest {
                    secret_key: &secret_key,
                    public_key: &public_key,
                    header: Some(header),
                    messages: Some(&messages[..]),
                })
                .expect("signature generation failed");

                group.bench_with_input(
                    BenchmarkId::new($ciphersuite, num_messages),
                    &num_messages,
                    |b, &_num_messages| {
                        b.iter(|| {
                            assert!($verify_fn(&BbsVerifyRequest {
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
            group.finish();
        }
    };
}

macro_rules! proof_gen_benchmark_generator {
    ($benchmark_fn:ident, $ciphersuite:literal, $sign_fn:ident, $verify_fn:ident, $proof_gen_fn:ident, $proof_verify_fn:ident) => {
        fn $benchmark_fn(c: &mut Criterion) {
            let header = TEST_HEADER.as_ref();
            let presentation_header = TEST_PRESENTATION_HEADER.as_ref();
            let (secret_key, public_key) = get_random_key_pair();

            let mut group =
                c.benchmark_group("BBS-Proof-Gen-Half-Disclosed-Messages");
            for num_messages in vec![1, 10, 100, 1000] {
                let num_revealed_messages = num_messages / 2;
                // generating random 100 bytes messages
                let mut messages = vec![[0u8; 100]; num_messages];
                for m in messages.iter_mut() {
                    rand::thread_rng().fill_bytes(m);
                }
                let messages: Vec<&[u8]> =
                    messages.iter().map(|m| m.as_ref()).collect();

                let signature = $sign_fn(&BbsSignRequest {
                    secret_key: &secret_key,
                    public_key: &public_key,
                    header: Some(header),
                    messages: Some(messages.as_slice()),
                })
                .expect("signature generation failed");

                assert_eq!(
                    $verify_fn(&BbsVerifyRequest {
                        public_key: &public_key,
                        header: Some(header),
                        messages: Some(messages.as_slice()),
                        signature: &signature,
                    })
                    .expect("error during signature verification"),
                    true
                );

                let mut proof_messages: Vec<
                    BbsProofGenRevealMessageRequest<_>,
                > = messages
                    .iter()
                    .map(|value| BbsProofGenRevealMessageRequest {
                        reveal: false,
                        value: value.clone(),
                    })
                    .collect();

                // Hide first 50% messages
                for i in 0..num_revealed_messages {
                    proof_messages[i].reveal = true;
                }

                group.bench_with_input(
                    BenchmarkId::new($ciphersuite, num_messages),
                    &num_messages,
                    |b, &_num_messages| {
                        b.iter(|| {
                            $proof_gen_fn(&BbsProofGenRequest {
                                public_key: black_box(&public_key),
                                header: Some(header),
                                messages: black_box(Some(&proof_messages)),
                                signature: black_box(&signature),
                                presentation_header: black_box(Some(
                                    presentation_header,
                                )),
                                verify_signature: None,
                            })
                            .unwrap();
                        });
                    },
                );
            }
            group.finish();
        }
    };
}

macro_rules! proof_verify_benchmark_generator {
    ($benchmark_fn:ident, $ciphersuite:literal, $sign_fn:ident, $verify_fn:ident, $proof_gen_fn:ident, $proof_verify_fn:ident) => {
        fn $benchmark_fn(c: &mut Criterion) {
            let header = TEST_HEADER.as_ref();
            let presentation_header = TEST_PRESENTATION_HEADER.as_ref();
            let (secret_key, public_key) = get_random_key_pair();

            let mut group =
                c.benchmark_group("BBS-Proof-Verify-Half-Disclosed-Messages");
            for num_messages in vec![1, 10, 100, 1000] {
                let num_revealed_messages = num_messages / 2;
                // generating random 100 bytes messages
                let mut messages = vec![[0u8; 100]; num_messages];
                for m in messages.iter_mut() {
                    rand::thread_rng().fill_bytes(m);
                }
                let messages: Vec<&[u8]> =
                    messages.iter().map(|m| m.as_ref()).collect();

                let signature = $sign_fn(&BbsSignRequest {
                    secret_key: &secret_key,
                    public_key: &public_key,
                    header: Some(header),
                    messages: Some(messages.as_slice()),
                })
                .expect("signature generation failed");

                assert_eq!(
                    $verify_fn(&BbsVerifyRequest {
                        public_key: &public_key,
                        header: Some(header),
                        messages: Some(messages.as_slice()),
                        signature: &signature,
                    })
                    .expect("error during signature verification"),
                    true
                );

                let mut proof_messages: Vec<
                    BbsProofGenRevealMessageRequest<_>,
                > = messages
                    .iter()
                    .map(|value| BbsProofGenRevealMessageRequest {
                        reveal: false,
                        value: value.clone(),
                    })
                    .collect();

                // Hide first 50% messages
                for i in 0..num_revealed_messages {
                    proof_messages[i].reveal = true;
                }
                // 50% revealed
                let revealed_messages = messages[0..num_revealed_messages]
                    .iter()
                    .enumerate()
                    .map(|(k, m)| (k as usize, m.clone()))
                    .collect::<Vec<(usize, &[u8])>>();

                let proof = $proof_gen_fn(&BbsProofGenRequest {
                    public_key: &public_key,
                    header: Some(header),
                    messages: Some(&proof_messages),
                    signature: &signature,
                    presentation_header: black_box(Some(presentation_header)),
                    verify_signature: None,
                })
                .expect("proof generation failed");

                group.bench_with_input(
                    BenchmarkId::new($ciphersuite, num_messages),
                    &num_messages,
                    |b, &_num_messages| {
                        b.iter(|| {
                            assert!($proof_verify_fn(&BbsProofVerifyRequest {
                                public_key: black_box(&public_key),
                                header: Some(header),
                                presentation_header: black_box(Some(
                                    presentation_header
                                )),
                                proof: black_box(&proof),
                                messages: black_box(Some(
                                    revealed_messages.as_slice()
                                )),
                            })
                            .unwrap());
                        });
                    },
                );
            }
            group.finish();
        }
    };
}

sign_benchmark_generator!(
    bls12_381_sha_256_sign_benchmark,
    "BLS12-381-SHA-256",
    bls12_381_sha_256_sign
);
sign_benchmark_generator!(
    bls12_381_shake_256_sign_benchmark,
    "BLS12-381-SHAKE-256",
    bls12_381_shake_256_sign
);
verify_benchmark_generator!(
    bls12_381_sha_256_verify_benchmark,
    "BLS12-381-SHA-256",
    bls12_381_sha_256_sign,
    bls12_381_sha_256_verify
);
verify_benchmark_generator!(
    bls12_381_shake_256_verify_benchmark,
    "BLS12-381-SHAKE-256",
    bls12_381_shake_256_sign,
    bls12_381_shake_256_verify
);
proof_gen_benchmark_generator!(
    bls12_381_sha_256_proof_gen_benchmark,
    "BLS12-381-SHA-256",
    bls12_381_sha_256_sign,
    bls12_381_sha_256_verify,
    bls12_381_sha_256_proof_gen,
    bls12_381_sha_256_proof_verify
);
proof_gen_benchmark_generator!(
    bls12_381_shake_256_proof_gen_benchmark,
    "BLS12-381-SHAKE-256",
    bls12_381_shake_256_sign,
    bls12_381_shake_256_verify,
    bls12_381_shake_256_proof_gen,
    bls12_381_shake_256_proof_verify
);

proof_verify_benchmark_generator!(
    bls12_381_sha_256_proof_verify_benchmark,
    "BLS12-381-SHA-256",
    bls12_381_sha_256_sign,
    bls12_381_sha_256_verify,
    bls12_381_sha_256_proof_gen,
    bls12_381_sha_256_proof_verify
);
proof_verify_benchmark_generator!(
    bls12_381_shake_256_proof_verify_benchmark,
    "BLS12-381-SHAKE-256",
    bls12_381_shake_256_sign,
    bls12_381_shake_256_verify,
    bls12_381_shake_256_proof_gen,
    bls12_381_shake_256_proof_verify
);

criterion_group!(
    name = bbs_api_benches;
    config = Criterion::default().measurement_time(Duration::from_secs(20));
    targets = bls12_381_sha_256_sign_benchmark,
              bls12_381_shake_256_sign_benchmark,
              bls12_381_sha_256_verify_benchmark,
              bls12_381_shake_256_verify_benchmark,
              bls12_381_sha_256_proof_gen_benchmark,
              bls12_381_shake_256_proof_gen_benchmark,
              bls12_381_sha_256_proof_verify_benchmark,
              bls12_381_shake_256_proof_verify_benchmark
);
criterion_main!(bbs_api_benches);
