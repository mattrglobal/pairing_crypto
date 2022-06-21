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
use rand::{rngs::OsRng, Rng};

const TEST_HEADER: &[u8; 16] = b"some_app_context";
const TEST_PRESENTATION_MESSAGE: &[u8; 25] = b"test-presentation-message";

fn proof_all_hidden_benchmark(c: &mut Criterion) {
    let (secret_key, public_key) = KeyPair::random(&mut OsRng)
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

        let signature = sign(BbsSignRequest {
            secret_key: secret_key.clone(),
            public_key: public_key.clone(),
            header: Some(TEST_HEADER.as_ref().to_vec()),
            messages: Some(messages.to_vec()),
        })
        .expect("signature generation failed");

        assert_eq!(
            verify(BbsVerifyRequest {
                public_key: public_key.clone(),
                header: Some(TEST_HEADER.as_ref().to_vec()),
                messages: Some(messages.to_vec()),
                signature: signature.to_vec(),
            })
            .expect("error during signature verification"),
            true
        );

        // All hidden
        let proof_messages: Vec<BbsProofGenRevealMessageRequest> = messages
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
                    proof_gen(BbsProofGenRequest {
                        public_key: black_box(public_key.clone()),
                        header: black_box(Some(TEST_HEADER.to_vec())),
                        messages: black_box(Some(proof_messages.clone())),
                        signature: black_box(signature.to_vec()),
                        presentation_message: black_box(Some(
                            TEST_PRESENTATION_MESSAGE.to_vec(),
                        )),
                    })
                    .unwrap();
                });
            },
        );

        let proof = proof_gen(BbsProofGenRequest {
            public_key: public_key.clone(),
            header: Some(TEST_HEADER.to_vec()),
            messages: Some(proof_messages.clone()),
            signature: signature.to_vec(),
            presentation_message: Some(TEST_PRESENTATION_MESSAGE.to_vec()),
        })
        .expect("proof generation failed");

        c.bench_function(
            &format!(
                "proof_verify all hidden - total messages {}",
                num_messages
            ),
            |b| {
                b.iter(|| {
                    assert!(proof_verify(BbsProofVerifyRequest {
                        public_key: black_box(public_key.clone()),
                        header: black_box(Some(TEST_HEADER.to_vec())),
                        presentation_message: black_box(Some(
                            TEST_PRESENTATION_MESSAGE.to_vec()
                        )),
                        proof: black_box(proof.clone()),
                        total_message_count: black_box(num_messages),
                        messages: black_box(Some(vec![])),
                    })
                    .unwrap());
                });
            },
        );
    }
}

fn proof_50_percent_revealed_benchmark(c: &mut Criterion) {
    let (secret_key, public_key) = KeyPair::random(&mut OsRng)
        .map(|key_pair| {
            (
                key_pair.secret_key.to_bytes().to_vec(),
                key_pair.public_key.point_to_octets().to_vec(),
            )
        })
        .expect("key generation failed");

    for num_messages in vec![1, 10, 100, 1000] {
        let num_revealed_messages = num_messages / 2;
        // generating random 32 bytes messages
        let messages: Vec<Vec<u8>> = (0..num_messages)
            .map(|_| rand::thread_rng().gen::<[u8; 32]>().to_vec())
            .collect();

        let signature = sign(BbsSignRequest {
            secret_key: secret_key.clone(),
            public_key: public_key.clone(),
            header: Some(TEST_HEADER.as_ref().to_vec()),
            messages: Some(messages.to_vec()),
        })
        .expect("signature generation failed");

        assert_eq!(
            verify(BbsVerifyRequest {
                public_key: public_key.clone(),
                header: Some(TEST_HEADER.as_ref().to_vec()),
                messages: Some(messages.to_vec()),
                signature: signature.to_vec(),
            })
            .expect("error during signature verification"),
            true
        );

        let mut proof_messages: Vec<BbsProofGenRevealMessageRequest> = messages
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
            .collect::<Vec<(usize, Vec<u8>)>>();

        c.bench_function(
            &format!(
                "proof_gen 50 percent revealed messages - total messages {}",
                num_messages
            ),
            |b| {
                b.iter(|| {
                    proof_gen(BbsProofGenRequest {
                        public_key: black_box(public_key.clone()),
                        header: black_box(Some(TEST_HEADER.to_vec())),
                        messages: black_box(Some(proof_messages.clone())),
                        signature: black_box(signature.to_vec()),
                        presentation_message: black_box(Some(
                            TEST_PRESENTATION_MESSAGE.to_vec(),
                        )),
                    })
                    .unwrap();
                });
            },
        );

        let proof = proof_gen(BbsProofGenRequest {
            public_key: public_key.clone(),
            header: Some(TEST_HEADER.to_vec()),
            messages: Some(proof_messages.clone()),
            signature: signature.to_vec(),
            presentation_message: Some(TEST_PRESENTATION_MESSAGE.to_vec()),
        })
        .expect("proof generation failed");

        c.bench_function(
            &format!(
                "proof_verify 50 percent revealed messages - total messages {}",
                num_messages
            ),
            |b| {
                b.iter(|| {
                    assert!(proof_verify(BbsProofVerifyRequest {
                        public_key: black_box(public_key.clone()),
                        header: black_box(Some(TEST_HEADER.to_vec())),
                        presentation_message: black_box(Some(
                            TEST_PRESENTATION_MESSAGE.to_vec()
                        )),
                        proof: black_box(proof.clone()),
                        total_message_count: black_box(num_messages),
                        messages: black_box(Some(revealed_messages.clone())),
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
