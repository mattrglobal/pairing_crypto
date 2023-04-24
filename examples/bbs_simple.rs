use std::collections::BTreeSet;

use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::KeyPair,
        bls12_381_g1_sha_256::{
            proof_gen as bls12_381_g1_sha_256_proof_gen,
            proof_verify as bls12_381_g1_sha_256_proof_verify,
            sign as bls12_381_g1_sha_256_sign,
            verify as bls12_381_g1_sha_256_verify,
        },
        bls12_381_g1_shake_256::{
            proof_gen as bls12_381_g1_shake_256_proof_gen,
            proof_verify as bls12_381_g1_shake_256_proof_verify,
            sign as bls12_381_g1_shake_256_sign,
            verify as bls12_381_g1_shake_256_verify,
        },
    },
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
};

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

const EXAMPLE_KEY_GEN_IKM: &[u8; 49] =
    b"only_for_example_not_A_random_seed_at_Allllllllll";
const EXAMPLE_KEY_INFO: &[u8; 16] = b"example-key-info";
const EXAMPLE_HEADER: &[u8; 14] = b"example-header";
const EXAMPLE_PRESENTATION_HEADER: &[u8; 27] = b"example-presentation-header";
const EXAMPLE_MESSAGES: [&[u8]; 2] =
    [b"example-message-1", b"example-message-2"];
const NUM_MESSAGES: usize = 2;

macro_rules! example {
        ($sign_fn:ident, $verify_fn:ident, $proof_gen_fn:ident, $proof_verify_fn:ident) => {
        info!("BBS signature example application");

        // generating random 32 bytes messages
        let messages = &EXAMPLE_MESSAGES;

        let (secret_key, public_key) = KeyPair::new(
        EXAMPLE_KEY_GEN_IKM,
        EXAMPLE_KEY_INFO)
        .map(|key_pair| {
            (
                key_pair.secret_key.to_bytes(),
                key_pair.public_key.to_octets(),
            )
        })
        .expect("key generation failed");

        let signature = $sign_fn(&BbsSignRequest {
            secret_key: &secret_key,
            public_key: &public_key,
            header: Some(EXAMPLE_HEADER.as_ref()),
            messages: Some(messages),
        })
        .expect("signature generation failed");

        assert_eq!(
            $verify_fn(&BbsVerifyRequest {
                public_key: &public_key,
                header: Some(EXAMPLE_HEADER.as_ref()),
                messages: Some(messages),
                signature: &signature,
            })
            .expect("error during signature verification"),
            true
        );

        let indices: Vec<usize> = (0..NUM_MESSAGES).collect();
        let indices_all_hidden = BTreeSet::<usize>::new();
        let indices_all_disclosed =
            indices.iter().cloned().collect::<BTreeSet<usize>>();
        let indices_first_disclosed = BTreeSet::<usize>::from([0]);
        let indices_last_disclosed = BTreeSet::<usize>::from([NUM_MESSAGES - 1]);

        let disclosed_indices_vector = [
            (indices_all_hidden, "all hidden indices"),
            (indices_all_disclosed, "all disclosed indices"),
            (indices_first_disclosed, "only first index disclosed"),
            (indices_last_disclosed, "only last index disclosed"),
        ];

        for (disclosed_indices, debug_info) in disclosed_indices_vector {
            info!("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            info!("proof scenario - {:?}", debug_info);
            let proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> = messages
                .iter()
                .enumerate()
                .map(|(index, message)| {
                    let mut reveal = false;
                    if disclosed_indices.contains(&index) {
                        reveal = true;
                    }
                    BbsProofGenRevealMessageRequest {
                        reveal,
                        value: message.clone(),
                    }
                })
                .collect();

            let disclosed_messages = proof_messages
                .iter()
                .enumerate()
                .filter(|(_, m)| m.reveal == true)
                .map(|(k, m)| (k as usize, m.value.clone()))
                .collect::<Vec<(usize, &[u8])>>();

            let proof = $proof_gen_fn(&BbsProofGenRequest {
                public_key: &public_key,
                header: Some(EXAMPLE_HEADER.as_ref()),
                messages: Some(&proof_messages),
                signature: &signature,
                presentation_header: Some(EXAMPLE_PRESENTATION_HEADER.as_ref()),
                verify_signature: None,
            })
            .expect("proof generation failed");

            assert!($proof_verify_fn(&BbsProofVerifyRequest {
                public_key: &public_key,
                header: Some(EXAMPLE_HEADER.as_ref()),
                presentation_header: Some(EXAMPLE_PRESENTATION_HEADER.as_ref()),
                proof: &proof,
                messages: Some(&disclosed_messages),
            })
            .unwrap());
            }
        }
    }

fn main() {
    pretty_env_logger::init();
    example!(
        bls12_381_g1_shake_256_sign,
        bls12_381_g1_shake_256_verify,
        bls12_381_g1_shake_256_proof_gen,
        bls12_381_g1_shake_256_proof_verify
    );

    example!(
        bls12_381_g1_sha_256_sign,
        bls12_381_g1_sha_256_verify,
        bls12_381_g1_sha_256_proof_gen,
        bls12_381_g1_sha_256_proof_verify
    );
}
