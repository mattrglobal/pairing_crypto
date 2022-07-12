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
use pprof::criterion::{Output, PProfProfiler};
use rand::Rng;

const KEY_GEN_SEED: &[u8; 32] = b"not_A_random_seed_at_Allllllllll";

const TEST_KEY_INFOS: &[u8; 50] =
    b"12345678901234567890123456789012345678901234567890";

const TEST_HEADER: &[u8; 16] = b"some_app_context";
const TEST_PRESENTATION_MESSAGE: &[u8; 25] = b"test-presentation-message";

const NUM_MESSAGES: usize = 1;
const NUM_REVEALED_MESSAGES: usize = 0;

fn profile_key_gen(c: &mut Criterion) {
    c.bench_function(&format!("profile - key_gen"), |b| {
        b.iter(|| {
            KeyPair::new(
                black_box(KEY_GEN_SEED.as_ref()),
                black_box(TEST_KEY_INFOS.as_ref()),
            )
            .map(|key_pair| {
                (
                    key_pair.secret_key.to_bytes(),
                    key_pair.public_key.to_octets(),
                )
            })
            .expect("key generation failed");
        });
    });
}

fn profile_sign(c: &mut Criterion) {
    // generating random 32 bytes messages
    let messages: Vec<Vec<u8>> = (0..NUM_MESSAGES)
        .map(|_| rand::thread_rng().gen::<[u8; 32]>().to_vec())
        .collect();

    let (secret_key, public_key) = KeyPair::new(
        black_box(KEY_GEN_SEED.as_ref()),
        black_box(TEST_KEY_INFOS.as_ref()),
    )
    .map(|key_pair| {
        (
            key_pair.secret_key.to_bytes(),
            key_pair.public_key.to_octets(),
        )
    })
    .expect("key generation failed");

    c.bench_function(
        &format!("profile - sign total messages {}", NUM_MESSAGES),
        |b| {
            b.iter(|| {
                sign(BbsSignRequest {
                    secret_key: &secret_key,
                    public_key: &public_key,
                    header: Some(TEST_HEADER.as_ref().to_vec()),
                    messages: Some(messages.to_vec()),
                })
                .unwrap();
            });
        },
    );
}

fn profile_verify(c: &mut Criterion) {
    // generating random 32 bytes messages
    let messages: Vec<Vec<u8>> = (0..NUM_MESSAGES)
        .map(|_| rand::thread_rng().gen::<[u8; 32]>().to_vec())
        .collect();

    let (secret_key, public_key) = KeyPair::new(
        black_box(KEY_GEN_SEED.as_ref()),
        black_box(TEST_KEY_INFOS.as_ref()),
    )
    .map(|key_pair| {
        (
            key_pair.secret_key.to_bytes(),
            key_pair.public_key.to_octets(),
        )
    })
    .expect("key generation failed");

    let signature = sign(BbsSignRequest {
        secret_key: &secret_key,
        public_key: &public_key,
        header: Some(TEST_HEADER.as_ref().to_vec()),
        messages: Some(messages.to_vec()),
    })
    .expect("signature generation failed");

    c.bench_function(
        &format!("profile - verify total messages {}", NUM_MESSAGES),
        |b| {
            b.iter(|| {
                assert!(verify(BbsVerifyRequest {
                    public_key: &public_key,
                    header: Some(TEST_HEADER.as_ref().to_vec()),
                    messages: Some(messages.to_vec()),
                    signature: &signature,
                })
                .unwrap(),);
            });
        },
    );
}

fn profile_proof_gen(c: &mut Criterion) {
    // generating random 32 bytes messages
    let messages: Vec<Vec<u8>> = (0..NUM_MESSAGES)
        .map(|_| rand::thread_rng().gen::<[u8; 32]>().to_vec())
        .collect();

    let (secret_key, public_key) = KeyPair::new(
        black_box(KEY_GEN_SEED.as_ref()),
        black_box(TEST_KEY_INFOS.as_ref()),
    )
    .map(|key_pair| {
        (
            key_pair.secret_key.to_bytes(),
            key_pair.public_key.to_octets(),
        )
    })
    .expect("key generation failed");

    let signature = sign(BbsSignRequest {
        secret_key: &secret_key,
        public_key: &public_key,
        header: Some(TEST_HEADER.as_ref().to_vec()),
        messages: Some(messages.to_vec()),
    })
    .expect("signature generation failed");

    assert_eq!(
        verify(BbsVerifyRequest {
            public_key: &public_key,
            header: Some(TEST_HEADER.as_ref().to_vec()),
            messages: Some(messages.to_vec()),
            signature: &signature,
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

    for i in 0..NUM_REVEALED_MESSAGES {
        proof_messages[i].reveal = true;
    }

    c.bench_function(
        &format!(
            "profile - proof_gen total messages {}, revealed messages {}",
            NUM_MESSAGES, NUM_REVEALED_MESSAGES
        ),
        |b| {
            b.iter(|| {
                proof_gen(BbsProofGenRequest {
                    public_key: &public_key,
                    header: Some(TEST_HEADER.to_vec()),
                    messages: Some(proof_messages.clone()),
                    signature: &signature,
                    presentation_message: Some(
                        TEST_PRESENTATION_MESSAGE.to_vec(),
                    ),
                })
                .unwrap();
            });
        },
    );
}

fn profile_proof_verify(c: &mut Criterion) {
    // generating random 32 bytes messages
    let messages: Vec<Vec<u8>> = (0..NUM_MESSAGES)
        .map(|_| rand::thread_rng().gen::<[u8; 32]>().to_vec())
        .collect();

    let (secret_key, public_key) = KeyPair::new(
        black_box(KEY_GEN_SEED.as_ref()),
        black_box(TEST_KEY_INFOS.as_ref()),
    )
    .map(|key_pair| {
        (
            key_pair.secret_key.to_bytes(),
            key_pair.public_key.to_octets(),
        )
    })
    .expect("key generation failed");

    let signature = sign(BbsSignRequest {
        secret_key: &secret_key,
        public_key: &public_key,
        header: Some(TEST_HEADER.as_ref().to_vec()),
        messages: Some(messages.to_vec()),
    })
    .expect("signature generation failed");

    assert_eq!(
        verify(BbsVerifyRequest {
            public_key: &public_key,
            header: Some(TEST_HEADER.as_ref().to_vec()),
            messages: Some(messages.to_vec()),
            signature: &signature,
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

    for i in 0..NUM_REVEALED_MESSAGES {
        proof_messages[i].reveal = true;
    }
    let revealed_messages = messages[0..NUM_REVEALED_MESSAGES]
        .iter()
        .enumerate()
        .map(|(k, m)| (k as usize, m.clone()))
        .collect::<Vec<(usize, Vec<u8>)>>();

    let proof = proof_gen(BbsProofGenRequest {
        public_key: &public_key,
        header: Some(TEST_HEADER.to_vec()),
        messages: Some(proof_messages.clone()),
        signature: &signature,
        presentation_message: Some(TEST_PRESENTATION_MESSAGE.to_vec()),
    })
    .expect("proof generation failed");

    c.bench_function(
        &format!(
            "profile - proof_verify total messages {}, revealed messages {}",
            NUM_MESSAGES, NUM_REVEALED_MESSAGES
        ),
        |b| {
            b.iter(|| {
                assert!(proof_verify(BbsProofVerifyRequest {
                    public_key: black_box(&public_key),
                    header: black_box(Some(TEST_HEADER.to_vec())),
                    presentation_message: black_box(Some(
                        TEST_PRESENTATION_MESSAGE.to_vec()
                    )),
                    proof: black_box(proof.clone()),
                    total_message_count: black_box(NUM_MESSAGES),
                    messages: black_box(Some(revealed_messages.clone())),
                })
                .unwrap());
            });
        },
    );
}

#[cfg(unix)]
criterion_group!(
    name = bbs_profile;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets =  profile_key_gen, profile_sign, profile_verify, profile_proof_gen, profile_proof_verify
);
#[cfg(not(unix))]
criterion_group!(
    name = bbs_profile;
    targets =  profile_key_gen, profile_sign, profile_verify, profile_proof_gen, profile_proof_verify
);
criterion_main!(bbs_profile);
