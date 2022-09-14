use pairing_crypto::{
    bbs::{
        ciphersuites::{
            bls12_381::KeyPair as BbsBls12381G1KeyPair,
            bls12_381_g1_sha_256::{
                bound_proof_gen as bls12_381_g1_sha_256_bound_proof_gen,
                bound_proof_verify as bls12_381_g1_sha_256_bound_proof_verify,
                bound_sign as bls12_381_g1_sha_256_bound_sign,
                bound_verify as bls12_381_g1_sha_256_bound_verify,
            },
            bls12_381_g1_shake_256::{
                bound_proof_gen as bls12_381_g1_shake_256_bound_proof_gen,
                bound_proof_verify as bls12_381_g1_shake_256_bound_proof_verify,
                bound_sign as bls12_381_g1_shake_256_bound_sign,
                bound_verify as bls12_381_g1_shake_256_bound_verify,
            },
        },
        BbsBoundProofGenRequest,
        BbsBoundSignRequest,
        BbsBoundVerifyRequest,
        BbsProofGenRevealMessageRequest,
        BbsProofVerifyRequest,
    },
    bls::ciphersuites::bls12_381::KeyPair as BlsSigBls12381G2KeyPair,
};

const TEST_KEY_GEN_SEED: &[u8; 32] = b"not_A_random_seed_at_Allllllllll";

const TEST_KEY_INFO: &[u8] = b"test-key-info";

const TEST_CLAIMS: [&[u8]; 6] = [
    b"first_name",
    b"surname",
    b"date_of_birth",
    b"father",
    b"mother",
    b"credential_id",
];

const TEST_HEADER: &[u8] = b"test-header";

const TEST_PRESENTATION_HEADER: &[u8; 24] = b"test-presentation-header";

macro_rules! bound_sign_verify_e2e_nominal {
    ($sign_fn:ident, $verify_fn:ident, $signature_test_vector:ident) => {
        let header = TEST_HEADER.as_ref();
        let messages = &TEST_CLAIMS;

        let (bbs_secret_key, bbs_public_key) = BbsBls12381G1KeyPair::new(
            TEST_KEY_GEN_SEED.as_ref(),
            Some(TEST_KEY_INFO),
        )
        .map(|key_pair| {
            (
                key_pair.secret_key.to_bytes(),
                key_pair.public_key.to_octets(),
            )
        })
        .expect("key generation failed");

        let (bls_sig_secret_key, bls_sig_public_key) =
            BlsSigBls12381G2KeyPair::new(
                TEST_KEY_GEN_SEED.as_ref(),
                Some(TEST_KEY_INFO),
            )
            .map(|key_pair| {
                (
                    key_pair.secret_key.to_bytes(),
                    key_pair.public_key.to_octets(),
                )
            })
            .expect("key generation failed");

        let signature = $sign_fn(&BbsBoundSignRequest {
            secret_key: &bbs_secret_key,
            public_key: &bbs_public_key,
            bls_public_key: &bls_sig_public_key,
            header: Some(header),
            messages: Some(messages),
        })
        .expect("signature generation failed");

        assert_eq!(
            $verify_fn(&BbsBoundVerifyRequest {
                public_key: &bbs_public_key,
                bls_secret_key: &bls_sig_secret_key,
                header: Some(header),
                messages: Some(messages),
                signature: &signature,
            })
            .expect("error during signature verification"),
            true
        );
    };
}

#[test]
fn bound_sign_verify_e2e_nominal() {
    bound_sign_verify_e2e_nominal!(
        bls12_381_g1_shake_256_bound_sign,
        bls12_381_g1_shake_256_bound_verify,
        EXPECTED_SIGNATURES_SHAKE_256
    );

    bound_sign_verify_e2e_nominal!(
        bls12_381_g1_sha_256_bound_sign,
        bls12_381_g1_sha_256_bound_verify,
        EXPECTED_SIGNATURES_SHA_256
    );
}

macro_rules! bound_proof_gen_verify_e2e_nominal {
    ($sign_fn:ident, $verify_fn:ident, $proof_gen_fn:ident, $proof_verify_fn:ident) => {
        let header = TEST_HEADER.as_ref();
        let presentation_header = TEST_PRESENTATION_HEADER.as_ref();
        let messages = &TEST_CLAIMS;

        let (bbs_secret_key, bbs_public_key) = BbsBls12381G1KeyPair::new(
            TEST_KEY_GEN_SEED.as_ref(),
            Some(TEST_KEY_INFO),
        )
        .map(|key_pair| {
            (
                key_pair.secret_key.to_bytes(),
                key_pair.public_key.to_octets(),
            )
        })
        .expect("key generation failed");

        let (bls_sig_secret_key, bls_sig_public_key) =
            BlsSigBls12381G2KeyPair::new(
                TEST_KEY_GEN_SEED.as_ref(),
                Some(TEST_KEY_INFO),
            )
            .map(|key_pair| {
                (
                    key_pair.secret_key.to_bytes(),
                    key_pair.public_key.to_octets(),
                )
            })
            .expect("key generation failed");

        let signature = $sign_fn(&BbsBoundSignRequest {
            secret_key: &bbs_secret_key,
            public_key: &bbs_public_key,
            bls_public_key: &bls_sig_public_key,
            header: Some(header),
            messages: Some(messages),
        })
        .expect("signature generation failed");

        assert_eq!(
            $verify_fn(&BbsBoundVerifyRequest {
                public_key: &bbs_public_key,
                bls_secret_key: &bls_sig_secret_key,
                header: Some(header),
                messages: Some(messages),
                signature: &signature,
            })
            .expect("error during signature verification"),
            true
        );

        // Start with all hidden messages
        let mut proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> =
            messages
                .iter()
                .map(|value| BbsProofGenRevealMessageRequest {
                    reveal: false,
                    value: value.clone(),
                })
                .collect();

        // Reveal 1 message at a time
        for j in 0..proof_messages.len() {
            let proof = &$proof_gen_fn(&BbsBoundProofGenRequest {
                public_key: &bbs_public_key,
                bls_secret_key: &bls_sig_secret_key,
                header: Some(header),
                messages: Some(&proof_messages),
                signature: &signature,
                presentation_header: Some(presentation_header),
                verify_signature: None,
            })
            .expect("proof generation failed");

            let mut revealed_msgs = Vec::new();
            for k in 0..j {
                revealed_msgs.push((k as usize, TEST_CLAIMS[k]));
            }

            assert_eq!(
                $proof_verify_fn(&BbsProofVerifyRequest {
                    public_key: &bbs_public_key,
                    header: Some(header),
                    presentation_header: Some(presentation_header),
                    proof: &proof,
                    total_message_count: messages.len(),
                    messages: Some(revealed_msgs.as_slice()),
                })
                .expect("proof verification failed"),
                true
            );
            proof_messages[j].reveal = true;
        }
    };
}

#[test]
fn bound_proof_gen_verify_e2e_nominal() {
    bound_proof_gen_verify_e2e_nominal!(
        bls12_381_g1_shake_256_bound_sign,
        bls12_381_g1_shake_256_bound_verify,
        bls12_381_g1_shake_256_bound_proof_gen,
        bls12_381_g1_shake_256_bound_proof_verify
    );

    bound_proof_gen_verify_e2e_nominal!(
        bls12_381_g1_sha_256_bound_sign,
        bls12_381_g1_sha_256_bound_verify,
        bls12_381_g1_sha_256_bound_proof_gen,
        bls12_381_g1_sha_256_bound_proof_verify
    );
}
