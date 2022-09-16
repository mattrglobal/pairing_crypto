use pairing_crypto::{
    bbs::{
        ciphersuites::{
            bls12_381::KeyPair,
            bls12_381_sha_256::{
                proof_gen as bls12_381_sha_256_proof_gen,
                proof_verify as bls12_381_sha_256_proof_verify,
                sign as bls12_381_sha_256_sign,
                verify as bls12_381_sha_256_verify,
            },
            bls12_381_shake_256::{
                proof_gen as bls12_381_shake_256_proof_gen,
                proof_verify as bls12_381_shake_256_proof_verify,
                sign as bls12_381_shake_256_sign,
                verify as bls12_381_shake_256_verify,
            },
        },
        BbsProofGenRequest, BbsProofGenRevealMessageRequest,
        BbsProofVerifyRequest, BbsSignRequest, BbsVerifyRequest,
    },
    Error,
};
use rand_core::OsRng;

const KEY_GEN_SEED: &[u8; 32] = b"not_A_random_seed_at_Allllllllll";

const TEST_KEY_INFOS: [&[u8]; 7] = [
    b"",
    b"abc",
    b"abcdefgh",
    b"abcdefghijklmnopqrstuvwxyz",
    b"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
    b"12345678901234567890123456789012345678901234567890",
    b"1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/",
];
const TEST_CLAIMS: [&[u8]; 6] = [
    b"first_name",
    b"surname",
    b"date_of_birth",
    b"father",
    b"mother",
    b"credential_id",
];

const TEST_PRESENTATION_HEADER: &[u8; 24] = b"test-presentation-header";

const EXPECTED_SIGNATURES_SHAKE_256: [&str; 7] = [
    "b6686e89636673c3f52d67dd39f0b39fbc7b82b4e7897bda124329a8e47efe27c984c775907c89cb34424b6a56dec2885f7c7bb68ed9c7bc06beaad407aa91b9dde1857355daf185b2d5e087d0fb966925cbeab0e69dbb58d0583383a1aafbd132129d4bde7521b35f9f459c36dd18aa",
    "b63fd2b7b7d092af3f1b1656d60a4415c3990f9de122a023a71ca941d72ac88c734f8804f5ef23e3a0f25d77e5e0669073cdc2955b18ce5b72d6961fb7671aa57ddb40ef9bf397aa21b5a4de0dd3a3cd24bf3f9a479960493d0493fa6eaf0d06488d7c858811e4d920ff4c7b5e7dfeb7",
    "a310d46e9ecad20c5cff4050cbe8066c93cf33496839b27eb1b8cbb91b4aac9b3e6cf6c3710097b4dfcc8208c2e775f21529099064d6a5169cdedeb03d3493ba41cdfbea998badcb2439076eca203803048760afcdf3c48098f8565070fdc504f2bcb56bb9ee8b1880be6225ebd292f7",
    "967b60f0f42f3017872521dbc133a99d530c8db274ad9bcfb6153a7fcb5e5b587d894cca9af3b1154fbc9d62ff09b2d33d85d0b49dd22e1f63fec5a508f97cc20bbf9aa943d2b0822ab053ac402387be0875705bdd57b95318d26676bad910f445f02e40e9f146b3ddb8c06898a41a3f",
    "a88f1503840d4a22d142b182083a4cb1ab54d40e8ceb9410958cf0804089aeb8f335728f635aa17a3ccb4d70d8bfe4774b1859b4667674e3821d00a7c40abf4b0837cc39bd3fa7faeccdc866b3bc1e6f38ee44b80aaf66db2b2bd0f1f23d5123f44bc6d4d2fddf6cf797c05165d36f3b",
    "983bcc97b3d37e2718a344f8c140b3bf7d744cb2de20c2a8b372f0f5e6e8ac0fcc5ad4fe3057e50c0525117d2a8fefba664c4035a11f85c291257596616ec600e02a7b76a7a0d5a31d880ad9ac69017f398232378a3488c9c1d9b2a2e3e74bee57237a05c8faf9c84696fecc3f58bd31",
    "a27cd6d07201615c8ea146d8237d5d193a3a4e9fb0cb8ce48f418a49f617da3db73a85bf86c29b3950dacd7566161cfd10e0f9353eb1642097dc08c522efc23886fd3b902bc4b58a8ace9acdeda472cb51d7302f3ea7f1a9eb05b54eea17c501d54cadca633de6a524522b22629947b6",    
];

const EXPECTED_SIGNATURES_SHA_256: [&str; 7] = [
    "896f2a38de3cc0e9c95432c35b2ba2148e44b39442f0e15c13e2c2ca52a7a62695a17495d4ab3f22d88abaf456a138e20fabf832b3abfc4db0075872f459a8a9db5504f0d86abd3227483ec28224e17a685adb2af8734479ae7e47b17c368425245abc8181a8580c9094268210a277fe",
    "8d57ace00102ff0de98d285b8dd16ccc8b82b9564b2031ec16c171db7a4fecb85b9cdb4f84023864b465b221d76534025877f74f29604a0f7ebb93ba2d723a6494d2244126efe8cd0dc4b037a2b12368297524bb3defa474550c288a8273f0c3d642b5726e3d370e5bc158c8401d9955",
    "a0338baa7cfab2ad6475c1da980e797e49fa346bc8ea5a383b64f30309463172504cb06d4e7d54beb7984a758bb642692b7e115b189902e78012b9a8d6fb609e7d66f9dbb12eac462fa1dfb712ee65fd418660ddcb18f9e78736f4476677a0a9744fdc9832d960452c2aeb24395cb003",
    "8b5fd9009a62b670e4712257e25900ebd8767119c4c0cdfd667e8aa1cf02cc3a9bba0aa67333e808a3eb3b2061408cbe4480b3e379dfb733094bd7b1113f312e008cabf023eb9e8668a5952be02c38490bbcd99a743ea7c132a1ee4a9b70c71bdd90525fecc808b3c17594f643ffbd03",
    "aa8670c6a30fa3adceffd491eaa19e8dd562a19ae574bceb058c1b197797a295f899aaa2d58ad8cffa6ce481ba5ff29f23cbfe87d44320906f8b19e2d8dd86d91f8d34d442c129b56673e8cbbc40abfd5c91c5584f1fd2d9a63f412e1628f43d1ca2e6ec22276a309d51b654a5b3086e",
    "ac8847187ed8725340d869dc76844dec8753ef02645051589b9739b910fb4b8bc78d60ecf02e94b07d4b578d8c4760e21a9d27171c8001e788e0743e4b6a46c99f7d4a835c6bb9eef2fcadcb0be92ed45589265c2b058d417c0ae882d1df38cc252b88dda075f80778dfb61613d1033e",
    "9121cf5fe6ddefb5f94f564bfd249d3967d6304a578fa2b5ff22314d9291ecef08c44690d35f3dab236b39b4f4e7bc034250b07fdc3b8d89fa45fd59c0aba386b4d75defa665e77a0cb69cad98c32c206a737e9620737d3673ea7248e174540da01451f5911e20a24a792482ca759918",
];

const TEST_HEADER: &[u8; 16] = b"some_app_context";

macro_rules! sign_verify_e2e_nominal {
    ($sign_fn:ident, $verify_fn:ident, $signature_test_vector:ident) => {
        let header = TEST_HEADER.as_ref();
        let messages = &TEST_CLAIMS;

        for i in 0..TEST_KEY_INFOS.len() {
            let (secret_key, public_key) =
                KeyPair::new(KEY_GEN_SEED.as_ref(), Some(TEST_KEY_INFOS[i]))
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
                header: Some(header),
                messages: Some(messages),
            })
            .expect("signature generation failed");

            let expected_signature = hex::decode($signature_test_vector[i])
                .expect("hex decoding failed");
            assert_eq!(signature.to_vec(), expected_signature);
            // println!("{:?},", hex::encode(signature));

            assert_eq!(
                $verify_fn(&BbsVerifyRequest {
                    public_key: &public_key,
                    header: Some(header),
                    messages: Some(messages),
                    signature: &signature,
                })
                .expect("error during signature verification"),
                true
            );
        }
    };
}

#[test]
fn sign_verify_e2e_nominal() {
    sign_verify_e2e_nominal!(
        bls12_381_shake_256_sign,
        bls12_381_shake_256_verify,
        EXPECTED_SIGNATURES_SHAKE_256
    );

    sign_verify_e2e_nominal!(
        bls12_381_sha_256_sign,
        bls12_381_sha_256_verify,
        EXPECTED_SIGNATURES_SHA_256
    );
}

macro_rules! proof_gen_verify_e2e_nominal {
    ($sign_fn:ident, $verify_fn:ident, $proof_gen_fn:ident, $proof_verify_fn:ident) => {
        let header = TEST_HEADER.as_ref();
        let presentation_header = TEST_PRESENTATION_HEADER.as_ref();
        let messages = &TEST_CLAIMS;

        for i in 0..TEST_KEY_INFOS.len() {
            let (secret_key, public_key) =
                KeyPair::new(KEY_GEN_SEED.as_ref(), Some(TEST_KEY_INFOS[i]))
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
                header: Some(header),
                messages: Some(messages),
            })
            .expect("signature generation failed");

            assert_eq!(
                $verify_fn(&BbsVerifyRequest {
                    public_key: &public_key,
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
                let proof = &$proof_gen_fn(&BbsProofGenRequest {
                    public_key: &public_key,
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
                        public_key: &public_key,
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
        }
    };
}

#[test]
fn proof_gen_verify_e2e_nominal() {
    proof_gen_verify_e2e_nominal!(
        bls12_381_shake_256_sign,
        bls12_381_shake_256_verify,
        bls12_381_shake_256_proof_gen,
        bls12_381_shake_256_proof_verify
    );

    proof_gen_verify_e2e_nominal!(
        bls12_381_sha_256_sign,
        bls12_381_sha_256_verify,
        bls12_381_sha_256_proof_gen,
        bls12_381_sha_256_proof_verify
    );
}

macro_rules! proof_gen_failure_message_modified {
    ($sign_fn:ident, $verify_fn:ident, $proof_gen_fn:ident) => {
        let num_disclosed_messages = 4;
        let header = TEST_HEADER.as_ref();
        let presentation_header = TEST_PRESENTATION_HEADER.as_ref();
        let messages = &TEST_CLAIMS;

        let (secret_key, public_key) = KeyPair::random(&mut OsRng, None)
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
            header: Some(header),
            messages: Some(messages),
        })
        .expect("signature generation failed");

        assert_eq!(
            $verify_fn(&BbsVerifyRequest {
                public_key: &public_key,
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

        let mut revealed_msgs = Vec::new();
        for i in 0..num_disclosed_messages {
            proof_messages[i].reveal = true;
            revealed_msgs.push((i as usize, TEST_CLAIMS[i].to_vec()));
        }

        // Modify one of the messages
        proof_messages[1].value = &[0xA; 50];

        // Proof-gen fails with tampered message when we pass `true` value for
        // `verify_signature`.
        let result = $proof_gen_fn(&BbsProofGenRequest {
            public_key: &public_key,
            header: Some(header),
            messages: Some(&proof_messages),
            signature: &signature,
            presentation_header: Some(presentation_header),
            verify_signature: Some(true),
        });
        assert_eq!(result, Err(Error::SignatureVerification));

        // Proof-gen succeeds with tampered message when we pass `false`value
        // for `verify_signature`.
        $proof_gen_fn(&BbsProofGenRequest {
            public_key: &public_key,
            header: Some(header),
            messages: Some(&proof_messages),
            signature: &signature,
            presentation_header: Some(presentation_header),
            verify_signature: Some(false),
        })
        .expect("proof should be generated for tampered messages");
    };
}

#[test]
fn proof_gen_failure_message_modified() {
    proof_gen_failure_message_modified!(
        bls12_381_shake_256_sign,
        bls12_381_shake_256_verify,
        bls12_381_shake_256_proof_gen
    );

    proof_gen_failure_message_modified!(
        bls12_381_sha_256_sign,
        bls12_381_sha_256_verify,
        bls12_381_sha_256_proof_gen
    );
}
