use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::KeyPair,
        bls12_381_shake_256::{
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

#[macro_use]
extern crate criterion;

use criterion::{black_box, Criterion};
use pprof::criterion::{Output, PProfProfiler};
use rand::RngCore;
use rand_core::OsRng;

const KEY_GEN_SEED: &[u8; 32] = b"not_A_random_seed_at_Allllllllll";

const TEST_KEY_INFOS: &[u8; 50] =
    b"12345678901234567890123456789012345678901234567890";

const TEST_HEADER: &[u8; 16] = b"some_app_context";
const TEST_PRESENTATION_HEADER: &[u8; 25] = b"test-presentation-header";

const NUM_MESSAGES: usize = 10;
const NUM_REVEALED_MESSAGES: usize = 5;

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

fn profile_key_gen(c: &mut Criterion) {
    c.bench_function(&format!("profile - key_gen"), |b| {
        b.iter(|| {
            KeyPair::new(
                black_box(KEY_GEN_SEED.as_ref()),
                black_box(Some(TEST_KEY_INFOS)),
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
    let header = TEST_HEADER.as_ref();
    let (secret_key, public_key) = get_random_key_pair();
    // generating random 100 bytes messages
    let mut messages = vec![[0u8; 100]; NUM_MESSAGES];
    for m in messages.iter_mut() {
        rand::thread_rng().fill_bytes(m);
    }
    let messages: Vec<&[u8]> = messages.iter().map(|m| m.as_ref()).collect();

    c.bench_function(
        &format!("profile - sign total messages {}", NUM_MESSAGES),
        |b| {
            b.iter(|| {
                bls12_381_shake_256_sign(&BbsSignRequest {
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

fn profile_verify(c: &mut Criterion) {
    let header = TEST_HEADER.as_ref();
    let (secret_key, public_key) = get_random_key_pair();
    // generating random 100 bytes messages
    let mut messages = vec![[0u8; 100]; NUM_MESSAGES];
    for m in messages.iter_mut() {
        rand::thread_rng().fill_bytes(m);
    }
    let messages: Vec<&[u8]> = messages.iter().map(|m| m.as_ref()).collect();

    let signature = bls12_381_shake_256_sign(&BbsSignRequest {
        secret_key: &secret_key,
        public_key: &public_key,
        header: Some(header),
        messages: Some(messages.as_slice()),
    })
    .expect("signature generation failed");

    c.bench_function(
        &format!("profile - verify total messages {}", NUM_MESSAGES),
        |b| {
            b.iter(|| {
                assert!(bls12_381_shake_256_verify(&BbsVerifyRequest {
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

fn profile_proof_gen(c: &mut Criterion) {
    let header = TEST_HEADER.as_ref();
    let presentation_header = TEST_PRESENTATION_HEADER.as_ref();
    let (secret_key, public_key) = get_random_key_pair();
    // generating random 100 bytes messages
    let mut messages = vec![[0u8; 100]; NUM_MESSAGES];
    for m in messages.iter_mut() {
        rand::thread_rng().fill_bytes(m);
    }
    let messages: Vec<&[u8]> = messages.iter().map(|m| m.as_ref()).collect();

    let signature = bls12_381_shake_256_sign(&BbsSignRequest {
        secret_key: &secret_key,
        public_key: &public_key,
        header: Some(header),
        messages: Some(messages.as_slice()),
    })
    .expect("signature generation failed");

    assert_eq!(
        bls12_381_shake_256_verify(&BbsVerifyRequest {
            public_key: &public_key,
            header: Some(header),
            messages: Some(messages.as_slice()),
            signature: &signature,
        })
        .expect("error during signature verification"),
        true
    );

    let mut proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> = messages
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
                bls12_381_shake_256_proof_gen(&BbsProofGenRequest {
                    public_key: black_box(&public_key),
                    header: Some(header),
                    messages: black_box(Some(&proof_messages)),
                    signature: black_box(&signature),
                    presentation_header: black_box(Some(presentation_header)),
                })
                .unwrap();
            });
        },
    );
}

fn profile_proof_verify(c: &mut Criterion) {
    let header = TEST_HEADER.as_ref();
    let presentation_header = TEST_PRESENTATION_HEADER.as_ref();
    let (secret_key, public_key) = get_random_key_pair();
    // generating random 100 bytes messages
    let mut messages = vec![[0u8; 100]; NUM_MESSAGES];
    for m in messages.iter_mut() {
        rand::thread_rng().fill_bytes(m);
    }
    let messages: Vec<&[u8]> = messages.iter().map(|m| m.as_ref()).collect();

    let signature = bls12_381_shake_256_sign(&BbsSignRequest {
        secret_key: &secret_key,
        public_key: &public_key,
        header: Some(header),
        messages: Some(messages.as_slice()),
    })
    .expect("signature generation failed");

    assert_eq!(
        bls12_381_shake_256_verify(&BbsVerifyRequest {
            public_key: &public_key,
            header: Some(header),
            messages: Some(messages.as_slice()),
            signature: &signature,
        })
        .expect("error during signature verification"),
        true
    );

    let mut proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> = messages
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
        .collect::<Vec<(usize, &[u8])>>();

    let proof = bls12_381_shake_256_proof_gen(&BbsProofGenRequest {
        public_key: &public_key,
        header: Some(header),
        messages: Some(&proof_messages),
        signature: &signature,
        presentation_header: Some(presentation_header),
    })
    .expect("proof generation failed");

    c.bench_function(
        &format!(
            "profile - proof_verify total messages {}, revealed messages {}",
            NUM_MESSAGES, NUM_REVEALED_MESSAGES
        ),
        |b| {
            b.iter(|| {
                assert!(bls12_381_shake_256_proof_verify(
                    &BbsProofVerifyRequest {
                        public_key: black_box(&public_key),
                        header: Some(header),
                        presentation_header: black_box(Some(
                            presentation_header
                        )),
                        proof: black_box(&proof),
                        total_message_count: black_box(NUM_MESSAGES),
                        messages: black_box(Some(revealed_messages.as_slice())),
                    }
                )
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
