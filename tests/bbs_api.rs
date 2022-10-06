use pairing_crypto::{
    bbs::{
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
    "96bfa62541a1b6948d06aafd99138c23e7dfc0a7430bddd293ae9a2fbd49c1e5a271c54e34c699f47dddbcc493915c485f7c7bb68ed9c7bc06beaad407aa91b9dde1857355daf185b2d5e087d0fb966925cbeab0e69dbb58d0583383a1aafbd132129d4bde7521b35f9f459c36dd18aa",
    "a97d308a4541650969937d7f83436776264d658767a03515f4582d8dbb240ce7cf37481cad78588adfc3b801f9b8544373cdc2955b18ce5b72d6961fb7671aa57ddb40ef9bf397aa21b5a4de0dd3a3cd24bf3f9a479960493d0493fa6eaf0d06488d7c858811e4d920ff4c7b5e7dfeb7",
    "a0fe498f0c03982025276f94ea6067a1f462bc7702e59570402de2bc282944f25d3bb3580afdb8124182e1e1c1c1b43a1529099064d6a5169cdedeb03d3493ba41cdfbea998badcb2439076eca203803048760afcdf3c48098f8565070fdc504f2bcb56bb9ee8b1880be6225ebd292f7",
    "8205e68d4777ed538284005bd7540ede01c9b2b73a02ac1664fc9c35710110d0ef3915ab55c806f273ec72432f6376e23d85d0b49dd22e1f63fec5a508f97cc20bbf9aa943d2b0822ab053ac402387be0875705bdd57b95318d26676bad910f445f02e40e9f146b3ddb8c06898a41a3f",
    "8c48184488259cf00e9fdb94210e3fae8c26a2cebeaa4d5223f2dd5a5e4313b2cd88dcc41f08ebb4cb8b835d8bb20ee54b1859b4667674e3821d00a7c40abf4b0837cc39bd3fa7faeccdc866b3bc1e6f38ee44b80aaf66db2b2bd0f1f23d5123f44bc6d4d2fddf6cf797c05165d36f3b",
    "a675e0c1bfdd6777e3b390e082ae6880fb4d9e57b3fc97199e949b4134d969d3d3e703309fade19a25209ba8a5c81dd2664c4035a11f85c291257596616ec600e02a7b76a7a0d5a31d880ad9ac69017f398232378a3488c9c1d9b2a2e3e74bee57237a05c8faf9c84696fecc3f58bd31",
    "a61a017cd32d93dc37bd22778bdd2b56e49ff9cc7b451c45d02385e5322d1c10894f9b6000538faaf192c40988c960ef10e0f9353eb1642097dc08c522efc23886fd3b902bc4b58a8ace9acdeda472cb51d7302f3ea7f1a9eb05b54eea17c501d54cadca633de6a524522b22629947b6",
];

const EXPECTED_SIGNATURES_SHA_256: [&str; 7] = [
    "8721f2420eebd18d5d1c126f0aa32753e8bff7caabf6244633cb0862501194f887da7edae4c4683c4e818e23cbddb3ee0fabf832b3abfc4db0075872f459a8a9db5504f0d86abd3227483ec28224e17a685adb2af8734479ae7e47b17c368425245abc8181a8580c9094268210a277fe",
    "93b5c9d3094b3bb34508ef06e1ea61525c29dbe8bf763b10dd05c8952a267c9fca2bb29a531e97343511b3d58ad17d325877f74f29604a0f7ebb93ba2d723a6494d2244126efe8cd0dc4b037a2b12368297524bb3defa474550c288a8273f0c3d642b5726e3d370e5bc158c8401d9955",
    "b9a498633009b3c4baf3e9011fb2c342f054ba4ec2c2f6dec621dae13a939c89e31889a3bee2669c1f812a577a4f538f2b7e115b189902e78012b9a8d6fb609e7d66f9dbb12eac462fa1dfb712ee65fd418660ddcb18f9e78736f4476677a0a9744fdc9832d960452c2aeb24395cb003",
    "a991d3e1994f0f0c180177331560715a449db59d040a89389b4378676ee0a4576155492855350fe2ca1a51a754e6da5a4480b3e379dfb733094bd7b1113f312e008cabf023eb9e8668a5952be02c38490bbcd99a743ea7c132a1ee4a9b70c71bdd90525fecc808b3c17594f643ffbd03",
    "90170be426cd84493c32d582b56a474e59764e4d1907e4fcb7d5f43b0c8c14ed167f5c88420223a28eb15b7160e3806423cbfe87d44320906f8b19e2d8dd86d91f8d34d442c129b56673e8cbbc40abfd5c91c5584f1fd2d9a63f412e1628f43d1ca2e6ec22276a309d51b654a5b3086e",
    "970e45f95a283295fd68c4462e58d3511936f6586a33cba22296cd57a603e8abd8fcc0a31e8ee761ad867eb1c9ec3ea91a9d27171c8001e788e0743e4b6a46c99f7d4a835c6bb9eef2fcadcb0be92ed45589265c2b058d417c0ae882d1df38cc252b88dda075f80778dfb61613d1033e",
    "a0c975d17685f675ea403ba28ceb636eda7eb1c0dbaa5a66b4592b46a89e1e69790ed61621f3fbdc966fcceedeaa44334250b07fdc3b8d89fa45fd59c0aba386b4d75defa665e77a0cb69cad98c32c206a737e9620737d3673ea7248e174540da01451f5911e20a24a792482ca759918",
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
        bls12_381_g1_shake_256_sign,
        bls12_381_g1_shake_256_verify,
        EXPECTED_SIGNATURES_SHAKE_256
    );

    sign_verify_e2e_nominal!(
        bls12_381_g1_sha_256_sign,
        bls12_381_g1_sha_256_verify,
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
        bls12_381_g1_shake_256_sign,
        bls12_381_g1_shake_256_verify,
        bls12_381_g1_shake_256_proof_gen,
        bls12_381_g1_shake_256_proof_verify
    );

    proof_gen_verify_e2e_nominal!(
        bls12_381_g1_sha_256_sign,
        bls12_381_g1_sha_256_verify,
        bls12_381_g1_sha_256_proof_gen,
        bls12_381_g1_sha_256_proof_verify
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
        bls12_381_g1_shake_256_sign,
        bls12_381_g1_shake_256_verify,
        bls12_381_g1_shake_256_proof_gen
    );

    proof_gen_failure_message_modified!(
        bls12_381_g1_sha_256_sign,
        bls12_381_g1_sha_256_verify,
        bls12_381_g1_sha_256_proof_gen
    );
}
