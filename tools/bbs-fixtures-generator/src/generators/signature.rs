use pairing_crypto::bbs::{
    ciphersuites::bls12_381::{
        sign,
        verify,
        BbsSignRequest,
        BbsVerifyRequest,
        BBS_BLS12381G1_SIGNATURE_LENGTH,
    },
    core::key_pair::KeyPair,
};
use rand::{prelude::SliceRandom, rngs::OsRng, thread_rng};
use std::path::PathBuf;

use crate::{
    model::{ExpectedResult, FixtureGenInput, FixtureSignature},
    util::save_test_vector_to_file,
};

pub fn generate(fixture_gen_input: &FixtureGenInput, output_dir: &PathBuf) {
    let signature_single_message = sign(&BbsSignRequest {
        secret_key: &fixture_gen_input.key_pair.secret_key.to_bytes(),
        public_key: &fixture_gen_input.key_pair.public_key.to_octets(),
        header: Some(fixture_gen_input.header.clone()),
        messages: Some(&fixture_gen_input.messages[..1]),
    })
    .unwrap();

    let signature_multi_message = sign(&BbsSignRequest {
        secret_key: &fixture_gen_input.key_pair.secret_key.to_bytes(),
        public_key: &fixture_gen_input.key_pair.public_key.to_octets(),
        header: Some(fixture_gen_input.header.clone()),
        messages: Some(&fixture_gen_input.messages),
    })
    .unwrap();

    let fixture_scratch: FixtureSignature = fixture_gen_input.clone().into();

    // single message - valid case
    let fixture = FixtureSignature {
        case_name: "single message signature".to_owned(),
        messages: fixture_gen_input.messages[..1].to_vec(),
        signature: signature_single_message.to_vec(),
        result: ExpectedResult {
            valid: true,
            reason: None,
        },
        ..fixture_scratch.clone()
    };
    validate_fixture(&fixture);
    save_test_vector_to_file(&fixture, output_dir, "signature001.json");

    // single message - modified message
    let fixture = FixtureSignature {
        case_name: "single message signature".to_owned(),
        messages: fixture_gen_input.messages
            [fixture_gen_input.messages.len() - 1..]
            .to_vec(),
        signature: signature_single_message.to_vec(),
        result: ExpectedResult {
            valid: false,
            reason: Some("modified message".to_owned()),
        },
        ..fixture_scratch.clone()
    };
    validate_fixture(&fixture);
    save_test_vector_to_file(&fixture, output_dir, "signature002.json");

    // single message - extra unsigned message
    let fixture = FixtureSignature {
        case_name: "single message signature".to_owned(),
        messages: fixture_gen_input.messages[..2].to_vec(),
        signature: signature_single_message.to_vec(),
        result: ExpectedResult {
            valid: false,
            reason: Some("extra unsigned message".to_owned()),
        },
        ..fixture_scratch.clone()
    };
    validate_fixture(&fixture);
    save_test_vector_to_file(&fixture, output_dir, "signature003.json");

    // multi message - valid case
    let fixture = FixtureSignature {
        case_name: "multi-message signature".to_owned(),
        messages: fixture_gen_input.messages.to_vec(),
        signature: signature_multi_message.to_vec(),
        result: ExpectedResult {
            valid: true,
            reason: None,
        },
        ..fixture_scratch.clone()
    };
    validate_fixture(&fixture);
    save_test_vector_to_file(&fixture, output_dir, "signature004.json");

    // multi message - missing messages
    let fixture = FixtureSignature {
        case_name: "multi-message signature".to_owned(),
        messages: fixture_gen_input.messages[..2].to_vec(),
        signature: signature_multi_message.to_vec(),
        result: ExpectedResult {
            valid: false,
            reason: Some("missing messages".to_owned()),
        },
        ..fixture_scratch.clone()
    };
    validate_fixture(&fixture);
    save_test_vector_to_file(&fixture, output_dir, "signature005.json");

    // multi message - re-ordered messages
    let mut shuffled_messages = fixture_gen_input.messages.clone();
    shuffled_messages.shuffle(&mut thread_rng());

    let fixture = FixtureSignature {
        case_name: "multi-message signature".to_owned(),
        messages: shuffled_messages,
        signature: signature_multi_message.to_vec(),
        result: ExpectedResult {
            valid: false,
            reason: Some("re-ordered messages".to_owned()),
        },
        ..fixture_scratch.clone()
    };
    validate_fixture(&fixture);
    save_test_vector_to_file(&fixture, output_dir, "signature006.json");

    // multi message - wrong public key
    let key_pair =
        KeyPair::random(&mut OsRng, b"some-key-info".as_ref()).unwrap();
    let fixture = FixtureSignature {
        case_name: "multi-message signature".to_owned(),
        key_pair,
        messages: fixture_gen_input.messages[..2].to_vec(),
        signature: signature_multi_message.to_vec(),
        result: ExpectedResult {
            valid: false,
            reason: Some("wrong public key".to_owned()),
        },
        ..fixture_scratch.clone()
    };
    validate_fixture(&fixture);
    save_test_vector_to_file(&fixture, output_dir, "signature007.json");
}

// Validate generated fixture before saving to the file
fn validate_fixture(fixture: &FixtureSignature) {
    let result = verify(&BbsVerifyRequest {
        public_key: &fixture.key_pair.public_key.to_octets(),
        header: Some(fixture.header.clone()),
        messages: Some(&fixture.messages),
        signature: &<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH]>::try_from(
            fixture.signature.clone(),
        )
        .unwrap(),
    })
    .unwrap();

    assert_eq!(result, fixture.result.valid);
}
