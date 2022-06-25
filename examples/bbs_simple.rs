use pairing_crypto::bbs::{
    ciphersuites::bls12_381::{
        proof_gen,
        proof_verify,
        sign,
        verify,
        BbsProofGenRequest,
        BbsProofGenRevealMessageRequest,
        BbsProofVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
    core::key_pair::KeyPair,
};

use rand::Rng;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;

const EXAMPLE_KEY_GEN_IKM: &[u8; 49] =
    b"only_for_example_not_A_random_seed_at_Allllllllll";
const EXAMPLE_KEY_INFO: &[u8; 16] = b"example-key-info";
const EXAMPLE_HEADER: &[u8; 22] = b"example-header-message";
const EXAMPLE_PRESENTATION_MESSAGE: &[u8; 28] = b"example-presentation-message";
const NUM_MESSAGES: usize = 2;
const NUM_REVEALED_MESSAGES: usize = 1;

fn main() {
    pretty_env_logger::init();

    info!("BBS signature example application");
    info!(
        "total-messages: {NUM_MESSAGES}, revealed-messages: \
         {NUM_REVEALED_MESSAGES}"
    );

    // generating random 32 bytes messages
    let messages: Vec<Vec<u8>> = (0..NUM_MESSAGES)
        .map(|_| rand::thread_rng().gen::<[u8; 32]>().to_vec())
        .collect();

    let (secret_key, public_key) =
        KeyPair::new(EXAMPLE_KEY_GEN_IKM.as_ref(), EXAMPLE_KEY_INFO.as_ref())
            .map(|key_pair| {
                (
                    key_pair.secret_key.to_bytes().to_vec(),
                    key_pair.public_key.point_to_octets().to_vec(),
                )
            })
            .expect("key generation failed");

    let signature = sign(BbsSignRequest {
        secret_key: secret_key.clone(),
        public_key: public_key.clone(),
        header: Some(EXAMPLE_HEADER.as_ref().to_vec()),
        messages: Some(messages.to_vec()),
    })
    .expect("signature generation failed");

    assert_eq!(
        verify(BbsVerifyRequest {
            public_key: public_key.clone(),
            header: Some(EXAMPLE_HEADER.as_ref().to_vec()),
            messages: Some(messages.to_vec()),
            signature: signature.to_vec(),
        })
        .expect("error during signature verification"),
        true
    );

    let mut proof_messages: Vec<BbsProofGenRevealMessageRequest> = messages
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
        .collect::<Vec<(usize, Vec<u8>)>>();

    let proof = proof_gen(BbsProofGenRequest {
        public_key: public_key.clone(),
        header: Some(EXAMPLE_HEADER.to_vec()),
        messages: Some(proof_messages.clone()),
        signature: signature.to_vec(),
        presentation_message: Some(EXAMPLE_PRESENTATION_MESSAGE.to_vec()),
    })
    .expect("proof generation failed");

    assert!(proof_verify(BbsProofVerifyRequest {
        public_key: public_key.clone(),
        header: Some(EXAMPLE_HEADER.to_vec()),
        presentation_message: Some(EXAMPLE_PRESENTATION_MESSAGE.to_vec()),
        proof: proof.clone(),
        total_message_count: NUM_MESSAGES,
        messages: Some(revealed_messages.clone()),
    })
    .unwrap());
}
