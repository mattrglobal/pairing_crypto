use pairing_crypto::bbs::ciphersuites::bls12_381::{
    proof_gen,
    proof_verify,
    sign,
    verify,
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
    BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
    BBS_BLS12381G1_SECRET_KEY_LENGTH,
};
use std::{collections::BTreeSet, path::PathBuf};

use crate::{
    model::{ExpectedResult, FixtureGenInput, FixtureProof},
    util::save_test_vector_to_file,
};

pub fn generate(fixture_gen_input: &FixtureGenInput, output_dir: &PathBuf) {
    let secret_key = &fixture_gen_input.key_pair.secret_key.to_bytes();
    let public_key = &fixture_gen_input.key_pair.public_key.to_octets();
    let header = &fixture_gen_input.header.clone();
    let presentation_message = &fixture_gen_input.presentation_message.clone();

    let fixture_scratch: FixtureProof = fixture_gen_input.clone().into();

    // multi-message signature, all messages revealed proof
    let messages = &fixture_gen_input.messages;
    let disclosed_indices: BTreeSet<usize> =
        (0..messages.len()).map(|i| i).collect();
    let (proof, disclosed_messages) = proof_gen_helper(
        secret_key,
        public_key,
        header,
        presentation_message,
        messages,
        &disclosed_indices,
    );
    let fixture = FixtureProof {
        case_name: "multi-message signature, all messages revealed proof"
            .to_owned(),
        disclosed_messages,
        total_message_count: messages.len(),
        proof,
        result: ExpectedResult {
            valid: true,
            reason: None,
        },
        ..fixture_scratch.clone()
    };
    validate_fixture(&fixture);
    save_test_vector_to_file(&fixture, &output_dir.join("proof002.json"));
}

fn proof_gen_helper(
    secret_key: &[u8; BBS_BLS12381G1_SECRET_KEY_LENGTH],
    public_key: &[u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    header: &Vec<u8>,
    presentation_message: &Vec<u8>,
    messages: &Vec<Vec<u8>>,
    disclosed_indices: &BTreeSet<usize>,
) -> (Vec<u8>, Vec<(usize, Vec<u8>)>) {
    if disclosed_indices.len() > messages.len() {
        panic!("more disclosed indices than messages");
    }
    for i in disclosed_indices {
        if *i >= messages.len() {
            panic!("disclosed index greater than total number of messages");
        }
    }

    // Generate the signature
    let signature = sign(&BbsSignRequest {
        secret_key,
        public_key,
        header: Some(header.clone()),
        messages: Some(messages.as_slice()),
    })
    .unwrap();

    // Verify the generated signature - just for validation
    assert_eq!(
        verify(&BbsVerifyRequest {
            public_key,
            header: Some(header.clone()),
            messages: Some(messages.as_slice()),
            signature: &signature
        })
        .unwrap(),
        true
    );

    let mut proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> =
        Vec::new();
    let mut disclosed_messages: Vec<(usize, Vec<u8>)> = Vec::new();

    for (i, m) in messages.iter().enumerate() {
        if disclosed_indices.contains(&i) {
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

    // Generate the proof
    let proof = proof_gen(&BbsProofGenRequest {
        public_key,
        header: Some(header.clone()),
        presentation_message: Some(presentation_message.clone()),
        messages: Some(&proof_messages),
        signature: &signature,
    })
    .unwrap();

    // Verify the generated proof - just for validation
    assert_eq!(
        proof_verify(&BbsProofVerifyRequest {
            public_key,
            header: Some(header.clone()),
            presentation_message: Some(presentation_message.clone()),
            messages: Some(&disclosed_messages),
            total_message_count: messages.len(),
            proof: &proof,
        })
        .unwrap(),
        true
    );
    (proof, disclosed_messages)
}

// Validate generated fixture if `proof_verify` returns expected result before
// saving to the file
fn validate_fixture(fixture: &FixtureProof) {
    assert_eq!(
        proof_verify(&BbsProofVerifyRequest {
            public_key: &fixture.signer_public_key.to_octets(),
            header: Some(fixture.header.clone()),
            presentation_message: Some(fixture.presentation_message.clone()),
            messages: Some(&fixture.disclosed_messages),
            total_message_count: fixture.total_message_count,
            proof: &fixture.proof,
        })
        .unwrap(),
        fixture.result.valid
    );
}
