use bbs_fixtures_generator::{
    validate_proof_fixture,
    validate_signature_fixture,
    FixtureProof,
    FixtureSignature,
};
use pairing_crypto::{
    bbs::ciphersuites::bls12_381::{
        proof_gen,
        BbsProofGenRequest,
        BbsProofGenRevealMessageRequest,
        BBS_BLS12381G1_SIGNATURE_LENGTH,
    },
    ExpandMsgXof,
};
use sha3::Shake256;
use std::convert::TryFrom;

static SIGNATURE_FIXTURES_DIR: &'static str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/bbs",
    "/signature"
);

static PROOF_FIXTURES_DIR: &'static str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/bbs", "/proof");

const TEST_PRESENTATION_MESSAGE: &[u8; 25] = b"test-presentation-message";

#[test]
fn signature_verify_fixtures() {
    let fixtures_paths = std::fs::read_dir(SIGNATURE_FIXTURES_DIR).unwrap();

    for fixture_path in fixtures_paths {
        let fixture = {
            let text =
                std::fs::read_to_string(fixture_path.unwrap().path()).unwrap();
            serde_json::from_str::<FixtureSignature>(&text).unwrap()
        };

        validate_signature_fixture::<ExpandMsgXof<Shake256>>(&fixture);
    }
}

// Try to derive proof from signature-fixtures
#[test]
fn derive_proof_fixtures() {
    let fixtures_paths = std::fs::read_dir(SIGNATURE_FIXTURES_DIR).unwrap();

    for fixture_path in fixtures_paths {
        let fixture = {
            let text =
                std::fs::read_to_string(fixture_path.unwrap().path()).unwrap();
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
                let _proof = proof_gen::<_, ExpandMsgXof<Shake256>>(
                    &BbsProofGenRequest {
                        public_key: &fixture.key_pair.public_key.to_octets(),
                        header: Some(fixture.header.clone()),
                        presentation_message: Some(
                            (&TEST_PRESENTATION_MESSAGE).to_vec(),
                        ),
                        messages: Some(&test.0),
                        signature:
                            &<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH]>::try_from(
                                fixture.signature.clone(),
                            )
                            .unwrap(),
                    },
                )
                .expect(&format!(
                    "proof-generation should not fail, case: {}, - {}",
                    fixture.case_name, test.1
                ));
            }
        } else {
            let result =
                proof_gen::<_, ExpandMsgXof<Shake256>>(&BbsProofGenRequest {
                    public_key: &fixture.key_pair.public_key.to_octets(),
                    header: Some(fixture.header.clone()),
                    presentation_message: Some(
                        (&TEST_PRESENTATION_MESSAGE).to_vec(),
                    ),
                    messages: Some(&all_revealed_messages),
                    signature:
                        &<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH]>::try_from(
                            fixture.signature.clone(),
                        )
                        .unwrap(),
                });

            assert!(
                result.is_err(),
                "proof-generation should return error, case: {} but {:?}",
                fixture.case_name,
                fixture.result.reason
            );
        }
    }
}

#[test]
fn proof_verify_fixtures() {
    let fixtures_paths = std::fs::read_dir(PROOF_FIXTURES_DIR).unwrap();

    for fixture_path in fixtures_paths {
        let fixture = {
            let text =
                std::fs::read_to_string(fixture_path.unwrap().path()).unwrap();
            serde_json::from_str::<FixtureProof>(&text).unwrap()
        };

        validate_proof_fixture::<ExpandMsgXof<Shake256>>(&fixture);
    }
}
