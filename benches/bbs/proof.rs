use std::time::Duration;

use pairing_crypto::bbs::{
    ciphersuites::bls12_381::{
        proof_gen,
        proof_verify,
        sign,
        verify,
        BbsProofGenRequest,
        BbsProofGenRevealMessageRequest,
        BbsProofVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
    core::key_pair::KeyPair,
};

#[macro_use]
extern crate criterion;

use criterion::{black_box, Criterion};
use rand::{rngs::OsRng, RngCore};

const TEST_HEADER: &[u8; 16] = b"some_app_context";
const TEST_PRESENTATION_MESSAGE: &[u8; 25] = b"test-presentation-message";

const TEST_KEY_INFOS: &[u8; 50] =
    b"12345678901234567890123456789012345678901234567890";

fn get_random_key_pair() -> ([u8; 32], [u8; 96]) {
    KeyPair::random(&mut OsRng, TEST_KEY_INFOS.as_ref())
        .map(|key_pair| {
            (
                key_pair.secret_key.to_bytes(),
                key_pair.public_key.to_octets(),
            )
        })
        .expect("key generation failed")
}

fn proof_all_hidden_benchmark(c: &mut Criterion) {
    let header = TEST_HEADER.as_ref();
    let presentation_message = TEST_PRESENTATION_MESSAGE.as_ref();
    let (secret_key, public_key) = get_random_key_pair();

    for num_messages in vec![1, 10, 100, 1000] {
        // generating random 100 bytes messages
        let mut messages = vec![[0u8; 100]; num_messages];
        for m in messages.iter_mut() {
            rand::thread_rng().fill_bytes(m);
        }
        let messages: Vec<&[u8]> =
            messages.iter().map(|m| m.as_ref()).collect();

        let signature = sign(&BbsSignRequest {
            secret_key: &secret_key,
            public_key: &public_key,
            header: Some(header),
            messages: Some(messages.as_slice()),
        })
        .expect("signature generation failed");

        assert_eq!(
            verify(&BbsVerifyRequest {
                public_key: &public_key,
                header: Some(header),
                messages: Some(messages.as_slice()),
                signature: &signature,
            })
            .expect("error during signature verification"),
            true
        );

        // All hidden
        let proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> = messages
            .iter()
            .map(|value| BbsProofGenRevealMessageRequest {
                reveal: false,
                value: value.clone(),
            })
            .collect();

        c.bench_function(
            &format!("proof_gen all hidden - total messages {}", num_messages),
            |b| {
                b.iter(|| {
                    proof_gen(&BbsProofGenRequest {
                        public_key: black_box(&public_key),
                        header: black_box(Some(header)),
                        messages: black_box(Some(&proof_messages)),
                        signature: black_box(&signature),
                        presentation_message: black_box(Some(
                            presentation_message,
                        )),
                    })
                    .unwrap();
                });
            },
        );

        let proof = proof_gen(&BbsProofGenRequest {
            public_key: &public_key,
            header: Some(header),
            messages: Some(&proof_messages),
            signature: &signature,
            presentation_message: Some(presentation_message),
        })
        .expect("proof generation failed");

        c.bench_function(
            &format!(
                "proof_verify all hidden - total messages {}",
                num_messages
            ),
            |b| {
                b.iter(|| {
                    assert!(proof_verify(&BbsProofVerifyRequest {
                        public_key: black_box(&public_key),
                        header: Some(header),
                        presentation_message: black_box(Some(
                            presentation_message
                        )),
                        proof: black_box(&proof),
                        total_message_count: black_box(num_messages),
                        messages: black_box(Some(&vec![])),
                    })
                    .unwrap());
                });
            },
        );
    }
}

fn proof_50_percent_revealed_benchmark(c: &mut Criterion) {
    let header = TEST_HEADER.as_ref();
    let presentation_message = TEST_PRESENTATION_MESSAGE.as_ref();
    let (secret_key, public_key) = get_random_key_pair();

    for num_messages in vec![1, 10, 100, 1000] {
        let num_revealed_messages = num_messages / 2;
        // generating random 100 bytes messages
        let mut messages = vec![[0u8; 100]; num_messages];
        for m in messages.iter_mut() {
            rand::thread_rng().fill_bytes(m);
        }
        let messages: Vec<&[u8]> =
            messages.iter().map(|m| m.as_ref()).collect();

        let signature = sign(&BbsSignRequest {
            secret_key: &secret_key,
            public_key: &public_key,
            header: Some(header),
            messages: Some(messages.as_slice()),
        })
        .expect("signature generation failed");

        assert_eq!(
            verify(&BbsVerifyRequest {
                public_key: &public_key,
                header: Some(header),
                messages: Some(messages.as_slice()),
                signature: &signature,
            })
            .expect("error during signature verification"),
            true
        );

        let mut proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> =
            messages
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

        c.bench_function(
            &format!(
                "proof_gen 50 percent revealed messages - total messages {}",
                num_messages
            ),
            |b| {
                b.iter(|| {
                    proof_gen(&BbsProofGenRequest {
                        public_key: black_box(&public_key),
                        header: Some(header),
                        messages: black_box(Some(&proof_messages)),
                        signature: black_box(&signature),
                        presentation_message: black_box(Some(
                            presentation_message,
                        )),
                    })
                    .unwrap();
                });
            },
        );

        let proof = proof_gen(&BbsProofGenRequest {
            public_key: &public_key,
            header: Some(header),
            messages: Some(&proof_messages),
            signature: &signature,
            presentation_message: black_box(Some(presentation_message)),
        })
        .expect("proof generation failed");

        c.bench_function(
            &format!(
                "proof_verify 50 percent revealed messages - total messages {}",
                num_messages
            ),
            |b| {
                b.iter(|| {
                    assert!(proof_verify(&BbsProofVerifyRequest {
                        public_key: black_box(&public_key),
                        header: Some(header),
                        presentation_message: black_box(Some(
                            presentation_message
                        )),
                        proof: black_box(&proof),
                        total_message_count: black_box(num_messages),
                        messages: black_box(Some(revealed_messages.as_slice())),
                    })
                    .unwrap());
                });
            },
        );
    }
}

criterion_group!(
    name = bbs_proof_benches;
    config = Criterion::default().measurement_time(Duration::from_secs(100));
    targets =  proof_all_hidden_benchmark, proof_50_percent_revealed_benchmark
);
criterion_main!(bbs_proof_benches);
