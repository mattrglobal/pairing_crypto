use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::{KeyPair, BBS_BLS12381G1_SIGNATURE_LENGTH},
        bls12_381_g1_sha_256::{
            sign_with_trace as bls12_381_sha_256_sign,
            verify as bls12_381_sha_256_verify,
        },
        bls12_381_g1_shake_256::{
            sign_with_trace as bls12_381_shake_256_sign,
            verify as bls12_381_shake_256_verify,
        },
    },
    BbsSignRequest,
    BbsVerifyRequest,
    SignatureTrace,
};
use rand::{prelude::SliceRandom, thread_rng};
use std::path::Path;

use crate::{
    model::{ExpectedResult, FixtureGenInput, FixtureSignature},
    util::save_test_vector,
    SIGNATURE_FIXTURES_SUBDIR,
};

use super::key_pair::{
    sha256_bbs_key_gen_tool as bls12_381_sha_256_key_gen,
    shake256_bbs_key_gen_tool as bls12_381_shake_256_key_gen,
};

macro_rules! generate_signature_fixture {
    ($keygen_fn:ident, $sign_fn:ident, $verify_fn:ident, $fixture_gen_input:ident, $output_dir:expr) => {
        // Key pair
        let key_pair = $keygen_fn(
            &$fixture_gen_input.key_ikm,
            &$fixture_gen_input.key_info,
        )
        .unwrap();

        let mut trace = SignatureTrace::default();

        let fixture_scratch = FixtureSignature {
            key_pair: key_pair.clone(),
            ..FixtureSignature::from($fixture_gen_input.clone())
        };

        let signature_single_message = $sign_fn(
            &BbsSignRequest {
                secret_key: &key_pair.secret_key.to_bytes(),
                public_key: &key_pair.public_key.to_octets(),
                header: Some($fixture_gen_input.header.clone()),
                messages: Some(&$fixture_gen_input.messages[..1]),
            },
            Some(&mut trace),
        )
        .unwrap();

        // single message - valid case
        let mut fixture = FixtureSignature {
            case_name: "single message signature".to_owned(),
            messages: $fixture_gen_input.messages[..1].to_vec(),
            signature: signature_single_message.to_vec(),
            result: ExpectedResult {
                valid: true,
                reason: None,
            },
            trace: trace.clone(),
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("signature001.json"));

        // single message - modified message
        let mut fixture = FixtureSignature {
            case_name: "single message signature".to_owned(),
            messages: $fixture_gen_input.messages
                [$fixture_gen_input.messages.len() - 1..]
                .to_vec(),
            signature: signature_single_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("modified message".to_owned()),
            },
            trace: trace.clone(),
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("signature002.json"));

        // single message - extra unsigned message
        let mut fixture = FixtureSignature {
            case_name: "single message signature".to_owned(),
            messages: $fixture_gen_input.messages[..2].to_vec(),
            signature: signature_single_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("extra unsigned message".to_owned()),
            },
            trace: trace.clone(),
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("signature003.json"));

        let signature_multi_message = $sign_fn(
            &BbsSignRequest {
                secret_key: &key_pair.secret_key.to_bytes(),
                public_key: &key_pair.public_key.to_octets(),
                header: Some($fixture_gen_input.header.clone()),
                messages: Some(&$fixture_gen_input.messages),
            },
            Some(&mut trace),
        )
        .unwrap();

        // multi message - valid case
        let mut fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            messages: $fixture_gen_input.messages.to_vec(),
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: true,
                reason: None,
            },
            trace: trace.clone(),
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("signature004.json"));

        // multi message - missing messages
        let mut fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            messages: $fixture_gen_input.messages[..2].to_vec(),
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("missing messages".to_owned()),
            },
            trace: trace.clone(),
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("signature005.json"));

        // multi message - re-ordered messages
        let mut reversed_messages = $fixture_gen_input.messages.clone();
        reversed_messages.reverse();

        let mut fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            messages: reversed_messages,
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("re-ordered messages".to_owned()),
            },
            trace: trace.clone(),
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("signature006.json"));

        // multi message - wrong public key
        let spare_key_pair = $keygen_fn(
            &$fixture_gen_input.spare_key_ikm,
            &$fixture_gen_input.key_info,
        )
        .unwrap();
        let spare_key_pair = KeyPair {
            secret_key: key_pair.secret_key.clone(),
            public_key: spare_key_pair.public_key,
        };
        let mut fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            key_pair: spare_key_pair,
            messages: $fixture_gen_input.messages.to_vec(),
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("wrong public key".to_owned()),
            },
            trace: trace.clone(),
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("signature007.json"));

        // multi message - different header
        let mut header = $fixture_gen_input.header.clone();
        header.reverse();
        let mut fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            header,
            messages: $fixture_gen_input.messages.to_vec(),
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some("different header".to_owned()),
            },
            trace: trace.clone(),
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("signature008.json"));

        // multi message - randomly shuffled messages
        let mut shuffled_messages = $fixture_gen_input.messages.clone();
        shuffled_messages.shuffle(&mut thread_rng());

        let mut fixture = FixtureSignature {
            case_name: "multi-message signature".to_owned(),
            messages: shuffled_messages,
            signature: signature_multi_message.to_vec(),
            result: ExpectedResult {
                valid: false,
                reason: Some(
                    "re-ordered(randomly shuffled) messages".to_owned(),
                ),
            },
            trace: trace.clone(),
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("signature009.json"));

        let signature_multi_message_no_header = $sign_fn(
            &BbsSignRequest {
                secret_key: &key_pair.secret_key.to_bytes(),
                public_key: &key_pair.public_key.to_octets(),
                header: None,
                messages: Some(&$fixture_gen_input.messages),
            },
            Some(&mut trace),
        )
        .unwrap();

        // multi message - valid case - no header
        let mut fixture = FixtureSignature {
            case_name: "multi-message signature, no header".to_owned(),
            messages: $fixture_gen_input.messages.to_vec(),
            header: Vec::new(),
            signature: signature_multi_message_no_header.to_vec(),
            result: ExpectedResult {
                valid: true,
                reason: None,
            },
            trace,
            ..fixture_scratch.clone()
        };
        validate_signature_fixture!($verify_fn, &fixture);
        save_test_vector(&mut fixture, &$output_dir.join("signature010.json"));
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

pub fn generate(fixture_gen_input: &FixtureGenInput, output_dir: &Path) {
    generate_signature_fixture!(
        bls12_381_sha_256_key_gen,
        bls12_381_sha_256_sign,
        bls12_381_sha_256_verify,
        fixture_gen_input,
        output_dir
            .join("bls12_381_sha_256")
            .join(SIGNATURE_FIXTURES_SUBDIR)
    );

    generate_signature_fixture!(
        bls12_381_shake_256_key_gen,
        bls12_381_shake_256_sign,
        bls12_381_shake_256_verify,
        fixture_gen_input,
        output_dir
            .join("bls12_381_shake_256")
            .join(SIGNATURE_FIXTURES_SUBDIR)
    );
}
