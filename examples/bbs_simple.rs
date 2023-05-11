use pairing_crypto::{
    bbs::{
        ciphersuites::{
            bls12_381::KeyPair,
            bls12_381_g1_sha_256::{proof_gen, proof_verify, sign, verify},
        },
        BbsProofGenRequest,
        BbsProofGenRevealMessageRequest,
        BbsProofVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
    Error,
};
use std::collections::BTreeSet;

const EXAMPLE_KEY_GEN_IKM: &[u8; 49] =
    b"only_for_example_not_A_random_seed_at_Allllllllll";
const EXAMPLE_KEY_INFO: &[u8; 16] = b"example-key-info";
const EXAMPLE_HEADER: &[u8; 14] = b"example-header";
const EXAMPLE_PRESENTATION_HEADER: &[u8; 27] = b"example-presentation-header";
const EXAMPLE_MESSAGES: [&[u8]; 2] =
    [b"example-message-1", b"example-message-2"];

fn main() -> Result<(), Error> {
    let messages = EXAMPLE_MESSAGES;

    let (secret_key, public_key) =
        KeyPair::new(EXAMPLE_KEY_GEN_IKM, EXAMPLE_KEY_INFO)
            .map(|key_pair| {
                (
                    key_pair.secret_key.to_bytes(),
                    key_pair.public_key.to_octets(),
                )
            })
            .expect("key generation failed");

    let signature = sign(&BbsSignRequest {
        secret_key: &secret_key,
        public_key: &public_key,
        header: Some(EXAMPLE_HEADER.as_ref()),
        messages: Some(&messages),
    })?;

    let result = verify(&BbsVerifyRequest {
        public_key: &public_key,
        header: Some(EXAMPLE_HEADER.as_ref()),
        messages: Some(&messages),
        signature: &signature,
    })?;
    assert!(result);

    let indices_first_disclosed = BTreeSet::<usize>::from([0]);

    let proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> = messages
        .iter()
        .enumerate()
        .map(|(index, message)| {
            let mut reveal = false;
            if indices_first_disclosed.contains(&index) {
                reveal = true;
            }
            BbsProofGenRevealMessageRequest {
                reveal,
                value: *message,
            }
        })
        .collect();

    let disclosed_messages = proof_messages
        .iter()
        .enumerate()
        .filter(|(_, m)| m.reveal)
        .map(|(k, m)| (k, m.value))
        .collect::<Vec<(usize, &[u8])>>();

    let proof = proof_gen(&BbsProofGenRequest {
        public_key: &public_key,
        header: Some(EXAMPLE_HEADER.as_ref()),
        messages: Some(&proof_messages),
        signature: &signature,
        presentation_header: Some(EXAMPLE_PRESENTATION_HEADER.as_ref()),
        verify_signature: None,
    })?;

    let result = proof_verify(&BbsProofVerifyRequest {
        public_key: &public_key,
        header: Some(EXAMPLE_HEADER.as_ref()),
        presentation_header: Some(EXAMPLE_PRESENTATION_HEADER.as_ref()),
        proof: &proof,
        messages: Some(&disclosed_messages),
    })?;
    assert!(result);
    Ok(())
}
