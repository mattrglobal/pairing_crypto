use pairing_crypto::{
    bbs::{ciphersuites::bls12_381::KeyPair, BbsProofGenRevealMessageRequest},
    pseudonym::{
        api::dtos::{
            BbsProofGenRequest,
            BbsProofVerifyRequest,
            BbsPseudonymGenRequest,
            BbsSignRequest,
            BbsVerifyRequest,
        },
        ciphersuites::bls12_381_g1_sha_256::{
            proof_gen as bls12_381_g1_sha_256_proof_gen,
            proof_verify as bls12_381_g1_sha_256_proof_verify,
            pseudonym_gen as bls12_381_g1_sha_256_pseudonym_gen,
            sign as bls12_381_g1_sha_256_sign,
            verify as bls12_381_g1_sha_256_verify,
        },
    },
};

const TEST_KEY_GEN_SEED: &[u8; 35] = b"trust_me_im_a_totally_random_scalar";
const TEST_KEY_INFOS: [&[u8]; 7] = [
    b"",
    b"abc",
    b"abcdefgh",
    b"abcdefghijklmnopqrstuvwxyz",
    b"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
    b"12345678901234567890123456789012345678901234567890",
    b"1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/",
];

const TEST_CLAIMS: [&[u8]; 7] = [
    b"",
    b"first_name",
    b"surname",
    b"date_of_birth",
    b"father",
    b"mother",
    b"credential_id",
];

const TEST_HEADER: &[u8; 11] = b"test-header";

const TEST_PRESENTATION_HEADER: &[u8; 24] = b"test-presentation-header";

const TEST_VERIFIER_ID: &[u8; 24] = b"test-verifier-identifier";
const TEST_PROVER_ID: &[u8; 22] = b"test-prover-identifier";

const EXPECTED_SIGNATURE_SHA_256: [&str; 7] = [
    "b00a353780b1cd8fe46842d5714d79272e53125cf0c315a2a87b74ca46ef06027a30625044c071bf62d6fb0c0245a6bd2210ef2cd149cb7e0010739b9064aa666f70cf4a189182412fa4569f1f3bc6a3",
    "93f92920bd6d40b091481e6f73bd105e3445c2ac1e76751bcb4aae14569954754212ca69a1604497fe9218c7972e2a9b03de12d03bbe3ce07635d2b4e2d3a0dac65a4f80cb6e2b4a4a3addf0253a045e",
    "902a1ac4894d31f7baf974781e2c02c61d3b9d59db49ae3fcffddfebe03b877c7fb407316c2202e67d94463c59f5b49619a5371dcad985db400e920ca33be87aaa5a797010304c8c58b1a6f220aaee93",
    "81a3f5ff87c7ae53a4aa6cc8e2f4a43c498ca32fe6b15e7b4d3dd904bfa73ea6a4c7dde1e3930f112ff9441e5cc443e46495463be0df3291818e9f8718a745f422ec73e6fd395157d60a79a21eb20bbe",
    "ab2b4919a7fe9939f8989b2d874d754756e731b99b3d5423b9d2535842ed0f9e542e821e942e9ddf25242a9cbd69d86b58486c7aa6ef9cfbb4df206e9b66186ccc8684688c535405bde0ba29fe5b2135",
    "924c38d441d8b021bf47adcd555622c372b012ef616b18f61b356701835a0371825ee5d7a03417f5d6fd6a15d7e7b8a038e5a01ea493df76211b8d1a174eb81c8525ca86a3c0ab129052a85ea7832b2c",
    "927b8609124d5ae90f2f9333233aeecb9e85408b9285eb5b58c1f04969c46cbf01977d229e6186878d46115d734847510afefc4f9ea17bd865446926a09f1fcb1968c1562a3b3ad138a53d484e82c865",
];

macro_rules! nym_sign_verify_e2e_nominal {
    ($sign_fn:ident, $verify_fn:ident, $signature_test_vector:ident) => {
        let header: Vec<u8> = TEST_HEADER.to_vec();
        let messages = TEST_CLAIMS.map(|e| e.to_vec());

        for i in 0..TEST_KEY_INFOS.len() {
            let (secret_key, public_key) =
                KeyPair::new(TEST_KEY_GEN_SEED, TEST_KEY_INFOS[i])
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
                prover_id: TEST_PROVER_ID.to_vec(),
                header: Some(header.clone()),
                messages: Some(&messages),
            })
            .expect("signature generation failed");

            let expected_signature = hex::decode($signature_test_vector[i])
                .expect("signature hex decoding failed");
            assert_eq!(signature.to_vec(), expected_signature);
            // println!("{:?},", hex::encode(signature));

            assert!($verify_fn(&BbsVerifyRequest {
                public_key: &public_key,
                prover_id: TEST_PROVER_ID.to_vec(),
                header: Some(header.clone()),
                messages: Some(&messages),
                signature: &signature
            })
            .expect("signature verification failed"));
        }
    };
}

#[test]
fn sign_verify_e2e_nominal() {
    nym_sign_verify_e2e_nominal!(
        bls12_381_g1_sha_256_sign,
        bls12_381_g1_sha_256_verify,
        EXPECTED_SIGNATURE_SHA_256
    );
}

macro_rules! proof_gen_verify_e2e_nominal {
    (
        $sign_fn:ident,
        $verify_fn:ident,
        $proof_gen_fn:ident,
        $proof_verify_fn:ident,
        $pseudonym_gen:ident,
    ) => {
        let header: Vec<u8> = TEST_HEADER.to_vec();
        let presentation_header = TEST_PRESENTATION_HEADER.as_ref();
        let messages = TEST_CLAIMS.map(|e| e.to_vec());

        for i in 0..TEST_KEY_INFOS.len() {
            let (secret_key, public_key) =
                KeyPair::new(TEST_KEY_GEN_SEED, TEST_KEY_INFOS[i])
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
                prover_id: TEST_PROVER_ID.to_vec(),
                header: Some(header.clone()),
                messages: Some(&messages),
            })
            .expect("signature generation failed");

            assert!($verify_fn(&BbsVerifyRequest {
                public_key: &public_key,
                prover_id: TEST_PROVER_ID.to_vec(),
                header: Some(header.clone()),
                messages: Some(&messages),
                signature: &signature
            })
            .expect("signature verification failed"));

            let mut proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> =
                messages
                    .iter()
                    .map(|value| BbsProofGenRevealMessageRequest {
                        reveal: false,
                        value: value.clone(),
                    })
                    .collect();

            let pseudonym = $pseudonym_gen(&BbsPseudonymGenRequest {
                verifier_id: TEST_VERIFIER_ID.to_vec(),
                prover_id: TEST_PROVER_ID.to_vec(),
            })
            .expect("pseudonym generation failed");

            for j in 0..proof_messages.len() {
                let proof = &$proof_gen_fn(&BbsProofGenRequest {
                    public_key: &public_key,
                    prover_id: TEST_PROVER_ID.to_vec(),
                    verifier_id: TEST_VERIFIER_ID.to_vec(),
                    pseudonym: &pseudonym,
                    header: Some(header.clone()),
                    messages: Some(&proof_messages),
                    signature: &signature,
                    presentation_header: Some(presentation_header.to_vec()),
                    verify_signature: Some(true),
                })
                .expect("proof generation failed");

                let mut revealed_msgs = Vec::new();
                for k in 0..j {
                    revealed_msgs.push((k as usize, TEST_CLAIMS[k]));
                }

                assert!($proof_verify_fn(&BbsProofVerifyRequest {
                    public_key: &public_key,
                    verifier_id: TEST_VERIFIER_ID.as_slice(),
                    pseudonym: &pseudonym,
                    header: Some(&header.clone()),
                    presentation_header: Some(presentation_header),
                    proof: &proof,
                    messages: Some(&revealed_msgs),
                })
                .expect("proof verification failed"));

                proof_messages[j].reveal = true;
            }
        }
    };
}

#[test]
fn proof_gen_verify_e2e_nominal() {
    proof_gen_verify_e2e_nominal!(
        bls12_381_g1_sha_256_sign,
        bls12_381_g1_sha_256_verify,
        bls12_381_g1_sha_256_proof_gen,
        bls12_381_g1_sha_256_proof_verify,
        bls12_381_g1_sha_256_pseudonym_gen,
    );
}
