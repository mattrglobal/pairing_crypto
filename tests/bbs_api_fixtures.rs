use bbs_fixtures_generator::{
    validate_proof_fixture,
    validate_signature_fixture,
    FixtureProof,
    FixtureSignature,
};
use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
        bls12_381_g1_sha_256::{
            proof_gen as bls12_381_sha_256_proof_gen,
            proof_verify as bls12_381_sha_256_proof_verify,
            verify as bls12_381_sha_256_verify,
        },
        bls12_381_g1_shake_256::{
            proof_gen as bls12_381_shake_256_proof_gen,
            proof_verify as bls12_381_shake_256_proof_verify,
            verify as bls12_381_shake_256_verify,
        },
    },
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsVerifyRequest,
};

use std::{convert::TryFrom, path::Path};

static FIXTURES_DIR: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/bbs");

const TEST_PRESENTATION_HEADER: &[u8; 24] = b"test-presentation-header";

macro_rules! sign_verify_fixtures {
    ($verify_fn:ident, $signature_fixtures_dir:expr) => {
        let fixtures_paths =
            std::fs::read_dir($signature_fixtures_dir).unwrap();

        for fixture_path in fixtures_paths {
            println!("Fixture path = {:?}", fixture_path);
            let fixture = {
                let text =
                    std::fs::read_to_string(fixture_path.unwrap().path())
                        .unwrap();
                serde_json::from_str::<FixtureSignature>(&text).unwrap()
            };

            println!("fixture = {:?}", fixture);

            validate_signature_fixture!($verify_fn, &fixture);
        }
    };
}

#[test]
fn sign_verify_fixtures() {
    sign_verify_fixtures!(
        bls12_381_sha_256_verify,
        Path::new(FIXTURES_DIR)
            .join("bls12_381_sha_256")
            .join("signature")
    );
    sign_verify_fixtures!(
        bls12_381_shake_256_verify,
        Path::new(FIXTURES_DIR)
            .join("bls12_381_shake_256")
            .join("signature")
    );
}

// Try to derive proof from signature-fixtures
macro_rules! derive_proof_fixtures {
    ($proof_gen_fn:ident, $signature_fixtures_dir:expr) => {
        let fixtures_paths =
            std::fs::read_dir($signature_fixtures_dir).unwrap();

        for fixture_path in fixtures_paths {
            let fixture = {
                let text =
                    std::fs::read_to_string(fixture_path.unwrap().path())
                        .unwrap();
                serde_json::from_str::<FixtureSignature>(&text).unwrap()
            };

            let all_revealed_messages = fixture
                .messages
                .iter()
                .map(|m| BbsProofGenRevealMessageRequest {
                    reveal: true,
                    value: m.clone(),
                })
                .collect::<Vec<BbsProofGenRevealMessageRequest<_>>>();

            if fixture.result.valid {
                let all_hidden_messages = fixture
                    .messages
                    .iter()
                    .map(|m| BbsProofGenRevealMessageRequest {
                        reveal: false,
                        value: m.clone(),
                    })
                    .collect::<Vec<BbsProofGenRevealMessageRequest<_>>>();

                let mut test_vector = vec![
                    (all_revealed_messages, "all revealed messages"),
                    (all_hidden_messages, "all hidden messages"),
                ];

                if !fixture.messages.is_empty() {
                    let first_revealed_messages = fixture
                        .messages
                        .iter()
                        .enumerate()
                        .map(|(i, m)| {
                            let mut reveal = false;
                            if i == 0 {
                                reveal = true;
                            }
                            BbsProofGenRevealMessageRequest {
                                reveal,
                                value: m.clone(),
                            }
                        })
                        .collect::<Vec<BbsProofGenRevealMessageRequest<_>>>();

                    test_vector.push((
                        first_revealed_messages,
                        "first message is revealed",
                    ));
                }

                for test in test_vector {
                    let _proof =
                        $proof_gen_fn(
                            &BbsProofGenRequest {
                                public_key: &fixture
                                    .key_pair
                                    .public_key
                                    .to_octets(),
                                header: Some(fixture.header.clone()),
                                presentation_header: Some(
                                    (&TEST_PRESENTATION_HEADER).to_vec(),
                                ),
                                messages: Some(&test.0),
                                signature: &<[u8;
                                    BBS_BLS12381G1_SIGNATURE_LENGTH]>::try_from(
                                    fixture.signature.clone(),
                                )
                                .unwrap(),
                                verify_signature: Some(true),
                            },
                        )
                        .expect(&format!(
                            "proof-generation should not fail, case: {}, - {}",
                            fixture.case_name, test.1
                        ));
                }
            } else {
                let result = $proof_gen_fn(&BbsProofGenRequest {
                    public_key: &fixture.key_pair.public_key.to_octets(),
                    header: Some(fixture.header.clone()),
                    presentation_header: Some(
                        (&TEST_PRESENTATION_HEADER).to_vec(),
                    ),
                    messages: Some(&all_revealed_messages),
                    signature:
                        &<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH]>::try_from(
                            fixture.signature.clone(),
                        )
                        .unwrap(),
                    verify_signature: Some(true),
                });

                assert!(
                    result.is_err(),
                    "proof-generation should return error, case: {} but {:?}",
                    fixture.case_name,
                    fixture.result.reason
                );
            }
        }
    };
}

#[test]
fn derive_proof_fixtures() {
    derive_proof_fixtures!(
        bls12_381_sha_256_proof_gen,
        Path::new(FIXTURES_DIR)
            .join("bls12_381_sha_256")
            .join("signature")
    );
    derive_proof_fixtures!(
        bls12_381_shake_256_proof_gen,
        Path::new(FIXTURES_DIR)
            .join("bls12_381_shake_256")
            .join("signature")
    );
}

macro_rules! proof_verify_fixtures {
    ($proof_verify_fn:ident, $proof_fixtures_dir:expr) => {
        let fixtures_paths = std::fs::read_dir($proof_fixtures_dir).unwrap();

        for fixture_path in fixtures_paths {
            let fixture = {
                let text =
                    std::fs::read_to_string(fixture_path.unwrap().path())
                        .unwrap();
                serde_json::from_str::<FixtureProof>(&text).unwrap()
            };

            validate_proof_fixture!($proof_verify_fn, &fixture);
        }
    };
}

#[test]
fn proof_verify_fixtures() {
    proof_verify_fixtures!(
        bls12_381_sha_256_proof_verify,
        Path::new(FIXTURES_DIR)
            .join("bls12_381_sha_256")
            .join("proof")
    );
    proof_verify_fixtures!(
        bls12_381_shake_256_proof_verify,
        Path::new(FIXTURES_DIR)
            .join("bls12_381_shake_256")
            .join("proof")
    );
}
