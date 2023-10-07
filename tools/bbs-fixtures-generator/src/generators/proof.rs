use blstrs::hash_to_curve::{ExpandMsgXmd, ExpandMsgXof};
use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::BBS_BLS12381G1_EXPAND_LEN,
        bls12_381_g1_sha_256::{
            ciphersuite_id as bls12_381_sha_256_ciphersuite_id,
            proof_verify as bls12_381_sha_256_proof_verify,
            proof_with_rng_and_trace as bls12_381_sha_256_proof_gen,
            sign as bls12_381_sha_256_sign,
            verify as bls12_381_sha_256_verify,
            POINT_G1_OCTETS_LENGTH as BLS12381_SHA256_POINT_G1_OCTETS_LENGTH,
            SCALAR_OCTETS_LENGTH as BLS12381_SHA256_SCALAR_OCTETS_LENGTH,
        },
        bls12_381_g1_shake_256::{
            ciphersuite_id as bls12_381_shake_256_ciphersuite_id,
            proof_verify as bls12_381_shake_256_proof_verify,
            proof_with_rng_and_trace as bls12_381_shake_256_proof_gen,
            sign as bls12_381_shake_256_sign,
            verify as bls12_381_shake_256_verify,
            POINT_G1_OCTETS_LENGTH as BLS12381_SHAKE256_POINT_G1_OCTETS_LENGTH,
            SCALAR_OCTETS_LENGTH as BLS12381_SHAKE256_SCALAR_OCTETS_LENGTH,
        },
    },
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
    ProofTrace,
};
use rand::RngCore;
use sha2::Sha256;
use sha3::Shake256;
use std::{collections::BTreeSet, path::Path};

use crate::{
    mock_rng::{MockRng, MOCKED_RNG_DST, MOCKED_RNG_SEED},
    model::{ExpectedResult, FixtureGenInput, FixtureProof},
    util::save_test_vector,
    PROOF_FIXTURES_SUBDIR,
};

use super::key_pair::{
    sha256_bbs_key_gen_tool as bls12_381_sha_256_key_gen,
    shake256_bbs_key_gen_tool as bls12_381_shake_256_key_gen,
};

macro_rules! generate_proof_fixture {
    ($keygen_fn:ident,
     $sign_fn:ident,
     $verify_fn:ident,
     $proof_gen_fn:ident,
     $proof_verify_fn:ident,
     $ciphersuite_id:ident,
     $fixture_gen_input:ident,
     $output_dir:expr,
     $expander:ty,
     $point_g1_octets_length:ident,
     $scalar_octets_length:ident) => {
        // Key pair
        let key_pair = $keygen_fn(
            &$fixture_gen_input.key_ikm,
            &$fixture_gen_input.key_info,
        )
        .unwrap();

        let secret_key = &key_pair.secret_key.to_bytes();
        let public_key = &key_pair.public_key.to_octets();

        let header = &$fixture_gen_input.header.clone();
        let presentation_header =
            &$fixture_gen_input.presentation_header.clone();

        let fixture_scratch: FixtureProof = FixtureProof {
            signer_public_key: key_pair.public_key.clone(),
            ..FixtureProof::from($fixture_gen_input.clone())
        };

        // Generate fixture for positive test cases
        let fixture_data = [
            (
                "single message signature, single-message revealed proof"
                    .to_owned(),
                "proof001.json",
                header,
                presentation_header,
                &$fixture_gen_input.messages[0..1].to_vec(),
                BTreeSet::<usize>::from([0]),
                ExpectedResult {
                    valid: true,
                    reason: None,
                },
            ),
            (
                "multi-message signature, all messages revealed proof"
                    .to_owned(),
                "proof002.json",
                header,
                presentation_header,
                &$fixture_gen_input.messages,
                (0..$fixture_gen_input.messages.len()).map(|i| i).collect(),
                ExpectedResult {
                    valid: true,
                    reason: None,
                },
            ),
            (
                "multi-message signature, multiple messages revealed proof"
                    .to_owned(),
                "proof003.json",
                header,
                presentation_header,
                &$fixture_gen_input.messages,
                BTreeSet::<usize>::from([0, 2, 4, 6]),
                ExpectedResult {
                    valid: true,
                    reason: None,
                },
            ),
            (
                "multi-message signature, multiple messages revealed proof, \
                 no header"
                    .to_owned(),
                "proof014.json",
                &Vec::new(),
                presentation_header,
                &$fixture_gen_input.messages,
                BTreeSet::<usize>::from([0, 2, 4, 6]),
                ExpectedResult {
                    valid: true,
                    reason: None,
                },
            ),
            (
                "multi-message signature, multiple messages revealed proof, \
                 no presentation header"
                    .to_owned(),
                "proof015.json",
                header,
                &Vec::new(),
                &$fixture_gen_input.messages,
                BTreeSet::<usize>::from([0, 2, 4, 6]),
                ExpectedResult {
                    valid: true,
                    reason: None,
                },
            ),
        ];

        for (
            case_name,
            test_vector_file_name,
            header,
            presentation_header,
            messages,
            disclosed_indices,
            result,
        ) in fixture_data
        {
            let (proof, disclosed_messages, signature, trace) = proof_gen_helper!(
                $sign_fn,
                $verify_fn,
                $proof_gen_fn,
                $proof_verify_fn,
                secret_key,
                public_key,
                header,
                presentation_header,
                messages,
                $ciphersuite_id,
                &disclosed_indices,
                $expander,
                $point_g1_octets_length,
                $scalar_octets_length
            );
            let mut fixture = FixtureProof {
                case_name,
                header: header.clone(),
                signature: signature.to_vec(),
                presentation_header: presentation_header.clone(),
                disclosed_messages,
                proof,
                result,
                trace,
                ..fixture_scratch.clone()
            };
            validate_proof_fixture!($proof_verify_fn, &fixture);
            save_test_vector(
                &mut fixture,
                &$output_dir.join(test_vector_file_name),
            );
        }

        // Generate fixtures for negative test cases
        // multi-message signature, multiple messages revealed proof
        let messages = &$fixture_gen_input.messages;
        let disclosed_indices = BTreeSet::<usize>::from([0, 2, 4, 6]);
        let (proof, disclosed_messages, signature, trace) = proof_gen_helper!(
            $sign_fn,
            $verify_fn,
            $proof_gen_fn,
            $proof_verify_fn,
            secret_key,
            public_key,
            header,
            presentation_header,
            messages,
            $ciphersuite_id,
            &disclosed_indices,
            $expander,
            $point_g1_octets_length,
            $scalar_octets_length
        );
        let fixture_negative = FixtureProof {
            case_name: "multi-message signature, all messages revealed proof"
                .to_owned(),
            signature: signature.to_vec(),
            disclosed_messages: disclosed_messages.clone(),
            proof: proof.clone(),
            result: ExpectedResult {
                valid: true,
                reason: None,
            },
            trace,
            ..fixture_scratch.clone()
        };

        let mut presentation_header =
            $fixture_gen_input.presentation_header.clone();
        presentation_header.reverse();
        let mut fixture = FixtureProof {
            presentation_header,
            result: ExpectedResult {
                valid: false,
                reason: Some("different presentation header".to_owned()),
            },
            ..fixture_negative.clone()
        };
        validate_proof_fixture!($proof_verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("proof004.json"));

        // Spare Key pair
        let spare_key_pair = $keygen_fn(
            &$fixture_gen_input.spare_key_ikm,
            &$fixture_gen_input.key_info,
        )
        .unwrap();

        let mut fixture = FixtureProof {
            signer_public_key: spare_key_pair.public_key,
            result: ExpectedResult {
                valid: false,
                reason: Some("wrong public key".to_owned()),
            },
            ..fixture_negative.clone()
        };
        validate_proof_fixture!($proof_verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("proof005.json"));

        let mut modified_disclosed_messages = disclosed_messages.clone();
        let mut buffer = [0u8; 100];
        rand::thread_rng().fill_bytes(&mut buffer);
        modified_disclosed_messages[0].1 = buffer.to_vec();
        let mut fixture = FixtureProof {
            disclosed_messages: modified_disclosed_messages,
            result: ExpectedResult {
                valid: false,
                reason: Some("modified messages".to_owned()),
            },
            ..fixture_negative.clone()
        };
        validate_proof_fixture!($proof_verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("proof006.json"));

        let mut invalid_disclosed_messages = disclosed_messages.clone();
        invalid_disclosed_messages.push((9, messages[9].clone()));
        let mut fixture = FixtureProof {
            disclosed_messages: invalid_disclosed_messages,
            result: ExpectedResult {
                valid: false,
                reason: Some("extra message un-revealed in proof".to_owned()),
            },
            ..fixture_negative.clone()
        };
        validate_proof_fixture!($proof_verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("proof007.json"));

        let mut invalid_disclosed_messages = disclosed_messages.clone();
        invalid_disclosed_messages.push((9, messages[8].clone()));
        let mut fixture = FixtureProof {
            disclosed_messages: invalid_disclosed_messages,
            result: ExpectedResult {
                valid: false,
                reason: Some(
                    "extra message invalid message un-revealed in proof"
                        .to_owned(),
                ),
            },
            ..fixture_negative.clone()
        };
        validate_proof_fixture!($proof_verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("proof008.json"));

        let mut missing_disclosed_messages = disclosed_messages.clone();
        missing_disclosed_messages.remove(2);
        let mut fixture = FixtureProof {
            disclosed_messages: missing_disclosed_messages,
            result: ExpectedResult {
                valid: false,
                reason: Some("missing message revealed in proof".to_owned()),
            },
            ..fixture_negative.clone()
        };
        validate_proof_fixture!($proof_verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("proof009.json"));

        let mut swapped_disclosed_messages = disclosed_messages.clone();
        swapped_disclosed_messages[1].1 = disclosed_messages[3].1.clone();
        swapped_disclosed_messages[3].1 = disclosed_messages[1].1.clone();
        let mut fixture = FixtureProof {
            disclosed_messages: swapped_disclosed_messages,
            result: ExpectedResult {
                valid: false,
                reason: Some("re-ordered messages".to_owned()),
            },
            ..fixture_negative.clone()
        };
        validate_proof_fixture!($proof_verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("proof010.json"));

        let mut extra_disclosed_messages = disclosed_messages.clone();
        extra_disclosed_messages.push((9, messages[9].clone()));
        let mut fixture = FixtureProof {
            disclosed_messages: extra_disclosed_messages,
            result: ExpectedResult {
                valid: false,
                reason: Some(
                    "extra valid message, modified total message count"
                        .to_owned(),
                ),
            },
            ..fixture_negative.clone()
        };
        validate_proof_fixture!($proof_verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("proof011.json"));

        // truncated proof, one less undisclosed message
        let truncated_proof = &proof.clone()[..proof.len() - 32];
        let mut fixture = FixtureProof {
            proof: truncated_proof.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some(
                    "truncated proof, one less undisclosed message".to_owned(),
                ),
            },
            ..fixture_negative.clone()
        };
        validate_proof_fixture!($proof_verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("proof012.json"));

        let mut header = $fixture_gen_input.header.clone();
        header.reverse();
        let mut fixture = FixtureProof {
            header,
            result: ExpectedResult {
                valid: false,
                reason: Some("different header".to_owned()),
            },
            ..fixture_negative.clone()
        };
        validate_proof_fixture!($proof_verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("proof013.json"));
    };
}

macro_rules! proof_gen_helper {
    (
    $sign_fn:ident,
    $verify_fn:ident,
    $proof_gen_fn:ident,
    $proof_verify_fn:ident,
    $secret_key:ident,
    $public_key:ident,
    $header:ident,
    $presentation_header:ident,
    $messages:ident,
    $ciphersuite_id:ident,
    $disclosed_indices:expr,
    $expander:ty,
    $point_g1_octets_length:ident,
    $scalar_octets_length:ident
) => {{
        if $disclosed_indices.len() > $messages.len() {
            panic!("more disclosed indices than messages");
        }
        for i in $disclosed_indices {
            if *i >= $messages.len() {
                panic!("disclosed index greater than total number of messages");
            }
        }

        // Generate the signature
        let signature = $sign_fn(&BbsSignRequest {
            $secret_key,
            $public_key,
            header: Some($header.clone()),
            messages: Some($messages.as_slice()),
        })
        .unwrap();

        // Verify the generated signature - just for validation
        assert_eq!(
            $verify_fn(&BbsVerifyRequest {
                $public_key,
                header: Some($header.clone()),
                messages: Some($messages.as_slice()),
                signature: &signature
            })
            .unwrap(),
            true
        );

        let mut proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> =
            Vec::new();
        let mut disclosed_messages: Vec<(usize, Vec<u8>)> = Vec::new();

        for (i, m) in $messages.iter().enumerate() {
            if $disclosed_indices.contains(&i) {
                proof_messages.push(BbsProofGenRevealMessageRequest {
                    reveal: true,
                    value: m.clone(),
                });
                disclosed_messages.push((i, m.clone()));
            } else {
                proof_messages.push(BbsProofGenRevealMessageRequest {
                    reveal: false,
                    value: m.clone(),
                });
            }
        }

        // Mocked rng based on expand_message
        let dst = &[&$ciphersuite_id(), MOCKED_RNG_DST.as_bytes()].concat();
        let count = $messages.len() - $disclosed_indices.len() + 3;
        let mocked_rng = MockRng::<'_, $expander>::new(
            MOCKED_RNG_SEED.as_bytes(),
            dst,
            count,
            Some(BBS_BLS12381G1_EXPAND_LEN),
        );

        // Generate the proof using the mocked rng
        let mut trace = ProofTrace::default();

        let proof = $proof_gen_fn(
            &BbsProofGenRequest {
                $public_key,
                header: Some($header.clone()),
                presentation_header: Some($presentation_header.clone()),
                messages: Some(&proof_messages),
                signature: &signature,
                verify_signature: None,
            },
            mocked_rng,
            Some(&mut trace),
        )
        .unwrap();

        // Sanity check for the count value in the input of mocked_rng
        if (proof.len()
            != 2 * $point_g1_octets_length + count * $scalar_octets_length)
        {
            panic!(
                "Unexpected 'count' value in MockedRng during fixture proof \
                 generation"
            )
        }

        // Verify the generated proof - just for validation
        assert_eq!(
            $proof_verify_fn(&BbsProofVerifyRequest {
                $public_key,
                header: Some($header.clone()),
                presentation_header: Some($presentation_header.clone()),
                messages: Some(&disclosed_messages),
                proof: &proof,
            })
            .unwrap(),
            true
        );
        (proof, disclosed_messages, signature, trace)
    }};
}

/// Validate fixture if `api::proof_verify` returns expected result.
#[macro_export]
macro_rules! validate_proof_fixture {
    ($proof_verify_fn:ident, $fixture:expr) => {
        let result = $proof_verify_fn(&BbsProofVerifyRequest {
            public_key: &$fixture.signer_public_key.to_octets(),
            header: Some($fixture.header.clone()),
            presentation_header: Some($fixture.presentation_header.clone()),
            messages: Some(&$fixture.disclosed_messages),
            proof: &$fixture.proof,
        });

        if $fixture.result.valid {
            assert!(
                result.is_ok(),
                "proof-verify should not return error, case: {}",
                $fixture.case_name
            );

            assert_eq!(
                result.unwrap(),
                true,
                "proof-verify should return `true`, case: {} - {:?}",
                $fixture.case_name,
                $fixture.result.reason
            );
        } else {
            assert!(
                result.is_err() || (result.unwrap() == false),
                "validation failed, case: {} - {:?}",
                $fixture.case_name,
                $fixture.result.reason
            );
        }
    };
}

pub fn generate(fixture_gen_input: &FixtureGenInput, output_dir: &Path) {
    generate_proof_fixture!(
        bls12_381_sha_256_key_gen,
        bls12_381_sha_256_sign,
        bls12_381_sha_256_verify,
        bls12_381_sha_256_proof_gen,
        bls12_381_sha_256_proof_verify,
        bls12_381_sha_256_ciphersuite_id,
        fixture_gen_input,
        output_dir
            .join("bls12_381_sha_256")
            .join(PROOF_FIXTURES_SUBDIR),
        ExpandMsgXmd<Sha256>,
        BLS12381_SHA256_POINT_G1_OCTETS_LENGTH,
        BLS12381_SHA256_SCALAR_OCTETS_LENGTH
    );

    generate_proof_fixture!(
        bls12_381_shake_256_key_gen,
        bls12_381_shake_256_sign,
        bls12_381_shake_256_verify,
        bls12_381_shake_256_proof_gen,
        bls12_381_shake_256_proof_verify,
        bls12_381_shake_256_ciphersuite_id,
        fixture_gen_input,
        output_dir
            .join("bls12_381_shake_256")
            .join(PROOF_FIXTURES_SUBDIR),
        ExpandMsgXof<Shake256>,
        BLS12381_SHAKE256_POINT_G1_OCTETS_LENGTH,
        BLS12381_SHAKE256_SCALAR_OCTETS_LENGTH
    );
}
