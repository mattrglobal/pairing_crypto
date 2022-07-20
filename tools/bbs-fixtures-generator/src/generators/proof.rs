use pairing_crypto::bbs::ciphersuites::bls12_381::{
    proof_gen,
    sign,
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsSignRequest,
};
use std::path::PathBuf;

use crate::{
    model::{ExpectedResult, FixtureGenInput, FixtureProof},
    util::save_test_vector_to_file,
};

pub fn generate(fixture_gen_input: &FixtureGenInput, output_dir: &PathBuf) {
    let signature_multi_message = sign(&BbsSignRequest {
        secret_key: &fixture_gen_input.key_pair.secret_key.to_bytes(),
        public_key: &fixture_gen_input.key_pair.public_key.to_octets(),
        header: Some(fixture_gen_input.header.clone()),
        messages: Some(&fixture_gen_input.messages),
    })
    .unwrap();

    let proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> =
        fixture_gen_input
            .messages
            .iter()
            .map(|value| BbsProofGenRevealMessageRequest {
                reveal: false,
                value: value.clone(),
            })
            .collect();

    let proof = proof_gen(&BbsProofGenRequest {
        public_key: &fixture_gen_input.key_pair.public_key.to_octets(),
        header: Some(fixture_gen_input.header.clone()),
        presentation_message: Some(
            fixture_gen_input.presentation_message.clone(),
        ),
        messages: Some(&proof_messages),
        signature: &signature_multi_message,
    })
    .unwrap();

    let fixture_scratch: FixtureProof = fixture_gen_input.clone().into();
    let disclosed_messages = fixture_gen_input
        .messages
        .iter()
        .enumerate()
        .map(|(i, m)| (i, m.clone()))
        .collect::<Vec<(usize, Vec<u8>)>>();

    // multi-message signature, all messages revealed proof
    let fixture = FixtureProof {
        case_name: "multi-message signature, all messages revealed proof"
            .to_owned(),
        disclosed_messages,
        total_message_count: fixture_gen_input.messages.len(),
        proof,
        result: ExpectedResult {
            valid: true,
            reason: None,
        },
        ..fixture_scratch.clone()
    };
    save_test_vector_to_file(&fixture, &output_dir.join("proof002.json"));
}
