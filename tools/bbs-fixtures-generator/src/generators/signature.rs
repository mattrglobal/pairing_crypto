use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::{KeyPair, BBS_BLS12381G1_SIGNATURE_LENGTH},
        bls12_381_sha_256::{
            sign as bls12_381_sha_256_sign,
            verify as bls12_381_sha_256_verify,
        },
        bls12_381_shake_256::{
            sign as bls12_381_shake_256_sign,
            verify as bls12_381_shake_256_verify,
        },
    },
    BbsSignRequest,
    BbsVerifyRequest,
};
use rand::{prelude::SliceRandom, thread_rng};
use std::path::PathBuf;

use crate::{
    model::{ExpectedResult, FixtureGenInput, FixtureSignature},
    util::save_test_vector,
};

macro_rules! generate_signature_fixture {
    ($sign_fn:ident, $verify_fn:ident, $fixture_gen_input:ident, $output_dir:ident) => {
        let signature_single_message = $sign_fn(&BbsSignRequest {
            secret_key: &$fixture_gen_input.key_pair.secret_key.to_bytes(),
            public_key: &$fixture_gen_input.key_pair.public_key.to_octets(),
            header: Some($fixture_gen_input.header.clone()),
            messages: Some(&$fixture_gen_input.messages[..1]),
        })
        .unwrap();

        let signature_multi_message = $sign_fn(&BbsSignRequest {
            secret_key: &$fixture_gen_input.key_pair.secret_key.to_bytes(),
            public_key: &$fixture_gen_input.key_pair.public_key.to_octets(),
            header: Some($fixture_gen_input.header.clone()),
            messages: Some(&$fixture_gen_input.messages),
        })
        .unwrap();

        let fixture_scratch: FixtureSignature =
            $fixture_gen_input.clone().into();

        // single message - valid case
        let fixture = FixtureSignature {
            case_name: "single message signature".to_owned(),
            messages: $fixture_gen_input.messages[..1].to_vec(),
            signature: signature_single_message.to_vec(),
            result: ExpectedResult {
                valid: true,
                reason: None,
            },
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&fixture, &$output_dir.join("signature001.json"));

        // single message - modified message
        let fixture = FixtureSignature {
            case_name: "single message signature".to_owned(),
            messages: $fixture_gen_input.messages
                [$fixture_gen_input.messages.len() - 1..]
                .to_vec(),
            signature: signature_single_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("modified message".to_owned()),
            },
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&fixture, &$output_dir.join("signature002.json"));

        // single message - extra unsigned message
        let fixture = FixtureSignature {
            case_name: "single message signature".to_owned(),
            messages: $fixture_gen_input.messages[..2].to_vec(),
            signature: signature_single_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("extra unsigned message".to_owned()),
            },
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&fixture, &$output_dir.join("signature003.json"));

        // multi message - valid case
        let fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            messages: $fixture_gen_input.messages.to_vec(),
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: true,
                reason: None,
            },
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&fixture, &$output_dir.join("signature004.json"));

        // multi message - missing messages
        let fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            messages: $fixture_gen_input.messages[..2].to_vec(),
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("missing messages".to_owned()),
            },
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&fixture, &$output_dir.join("signature005.json"));

        // multi message - re-ordered messages
        let mut reversed_messages = $fixture_gen_input.messages.clone();
        reversed_messages.reverse();

        let fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            messages: reversed_messages,
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("re-ordered messages".to_owned()),
            },
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&fixture, &$output_dir.join("signature006.json"));

        // multi message - wrong public key
        let key_pair = KeyPair {
            secret_key: $fixture_gen_input.key_pair.secret_key.clone(),
            public_key: $fixture_gen_input.spare_key_pair.public_key,
        };
        let fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            key_pair,
            messages: $fixture_gen_input.messages.to_vec(),
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("wrong public key".to_owned()),
            },
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&fixture, &$output_dir.join("signature007.json"));

        // multi message - different header
        let mut header = $fixture_gen_input.header.clone();
        header.reverse();
        let fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            header,
            messages: $fixture_gen_input.messages.to_vec(),
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("different header".to_owned()),
            },
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&fixture, &$output_dir.join("signature008.json"));

        // multi message - randomly shuffled messages
        let mut shuffled_messages = $fixture_gen_input.messages.clone();
        shuffled_messages.shuffle(&mut thread_rng());

        let fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            messages: shuffled_messages,
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some(
                    "re-ordered(randomly shuffled) messages".to_owned(),
                ),
            },
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&fixture, &$output_dir.join("signature009.json"));
    };
}

/// Validate fixture if `api::verify` returns expected result.
#[macro_export]
macro_rules! validate_signature_fixture {
    ($verify_fn:ident, $fixture:expr) => {
        let result = $verify_fn(&BbsVerifyRequest {
            public_key: &$fixture.key_pair.public_key.to_octets(),
            header: Some($fixture.header.clone()),
            messages: Some(&$fixture.messages),
            signature: &<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH]>::try_from(
                $fixture.signature.clone(),
            )
            .unwrap(),
        })
        .expect(&format!(
            "verify should not return error, case: {}",
            $fixture.case_name
        ));

        assert_eq!(
            result, $fixture.result.valid,
            "validation failed, case: {} - {:?}",
            $fixture.case_name, $fixture.result.reason
        );
    };
}

pub fn generate(fixture_gen_input: &FixtureGenInput, output_dir: &PathBuf) {
    let ciphersuite_output_dir = output_dir.join("bls12_381_sha_256");
    generate_signature_fixture!(
        bls12_381_sha_256_sign,
        bls12_381_sha_256_verify,
        fixture_gen_input,
        ciphersuite_output_dir
    );

    let ciphersuite_output_dir = output_dir.join("bls12_381_shake_256");
    generate_signature_fixture!(
        bls12_381_shake_256_sign,
        bls12_381_shake_256_verify,
        fixture_gen_input,
        ciphersuite_output_dir
    );
}
