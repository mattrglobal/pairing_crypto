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
    "b64ec227bea2a197d5dd230942ec4caa69fcdbc2ae59283e98af6e60b592d1784ebd114381d35d1e64714394f169041867ef2367f4e4991dc262c99bedc7ea41c775d989ad99b8acfa1349c3adf6addd0bd0dc34b4c8819531e7ff97a705d183d585af964ce7a39b6a0edbd79cad1954",
    "8d963e689a01047ad115f9117b8d80ed863b50b27080ef3b6d36254246b7dc79c2b4c6648a838cd7874ee7e68100972f5d906380e2404127e8904cbfdf80fff81806aff4ef7eb93b3f261774f5bd735a31e6af6b7a3c30ca142b05320cbad686f8a27ee308ae6440ba935c18087dccb9",
    "a66eb1c22a68334d13ebf9c50e1e48c126d6fe3157bf42e3ffd32a481d86ec9c4d64e8841766be634354d027e0ba5d0b1160bd8e177b22a124027f95d6ad342c4d5e50e96f33112cdafd62a626c1917e5e1f863a8f6738cf4180786f76aaea64b00548b5e374660d736b119e3696dae9",
    "aa7bc05c5b4f17ad75e6a967a7e13969b739ddd8c935cb77bfb4b693c15296ce3010a82395eb57d9f712bc58170fbcd5507c170a773abfa8319fcb94d2df6d71169b44f8a2804b4353bcc82f05d2d6db255c289463942385c4b7910906cb5a8b61ea610bef081dc5d8830adc3db1f3c7",
    "a10e416b1d793fd9f1ad156676272a2927defc6604240c1938b18b1507e27bbbe317a48e0ced0c8c2c2d1180694f05902aed0881a936f7fcea82ba655244cd7e52b5a33e9f50006b383b4c2f15852c143f1f506e019aa8aeeeec2735d39c2cc560e1c55b98254696e58649e298d224e7",
    "88d099b4b662e40be9193234f9f0238ac47c761bb91bd5dc9f1903ec1379f56da2cf9a078419da3758f9d40cb466243a3beafb4a8da6b2fe16cc55297fe1ee7981a5f5e0fbc49cec46b91d4f7657c09d38f64472dd119b6e878a87d04ec494f615cbcde7ab564e10e371f99394a8fc2b",
    "b8a333fdfaf3ed738e76caf23280bae380c59cf141fd655d8b1efdd11114b1fe09d4ed6ee1570322cc24805d98b0911f5b8b6ec32701a693f41ed2356ec00d8f8a808109f14c08c0a2ed17ee1376a7c5621cf2cee53a64706ecbc7918ebe4815bc2a703f4c9f212fe64af8e275b6588b",
];

const EXPECTED_SIGNATURES_SHA_256: [&str; 7] = [
    "82df272d7165a2317eb61b9e601c788c491d70eaee23567971bcf20f29caa813d275066c38d10aa667429e78758f4e1d7361e023400ceb475bcf262b5e2127f82af72a231ff0a5ac388eb1d43983ca8e2f8857c916cb552ae1cce035b973932cecd009a36b2a36686a4b5bce919bcf42",
    "a4af4fbb4afc7cc1cbdf79dfa55229926959e585dcd908d931a755e005bab996ce77bb609aa77e2a587e6d03de0467f128b20218b0f9e51d049fb229c7f05013470be062ba89337133c3d04971f9e6be105213a29f0dd33e5c85f7bc4d9517af02fc3604db705650b747d637eaee4e4a",
    "a70f28e2dd62f1d11ab405469231fcf891774c08af81963e20674eb27c165581462100b6eda070dfc77fa2979028e47831f57a8e26c2f268b115ae6d54eb0377529645cf81404f1ab18a3944f9b3da3a50434333d085b1ed59fcfc8a4052c1002669a1dda889f111be1de330acfc9b0c",
    "8cb96ebd647466c7608e585fd0531741421af46b5dbb8884bf463eb3797f3b90fdbce64e45439185efe509a9e5cc50f72eb134a6f08e711ada1866a11c59598c1f4d3c415d1ad2a4f1aa74cdd5910b610fe9ea3f4d44a63779189a690cc53e2726d40bb351b0496f275edbf8081afc71",
    "92139206412834261e7e11b5febdd694a15a24621b1771ac7aa1654da8123e636a5aa09725f397c533ee108ac90b91f12a4fdc42db54870bd6a06653a2da250c28a0247d0cd6117e9ddf222441b92316545526b00b944e6fea7fd10204fe66f8641168c30d18cd7714ce185cc8b994b2",
    "b48403699296036eca39fe0e6c7e6161c25eba39bd503b5e1be8c0b7b1ed8f713b0f2d5752fc11ef5d5f16a25f014b890c850825545043db2b5d13976d73caeb18999b69f687a52e648aa11000b880a65f3e85dba751c4e336d47daba9a26d618d7cd3f2bb5bdbb71630c515cfad8ee5",
    "89a77da242dfb2226b660693be092cffb1ddc9e7275f1eb150e64756c39649e429d973def61bb91a289d8f45e09add2f1b7fc0864b3348bf1fa3d0ad95a0c4527f888766085c21d71268b4ef2665b3022a53c9d1396f5ab7f0f8ebb99bcc87784c07283adff8abb7fdb27c1dbba6699c",
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
