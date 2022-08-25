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
    "b8d7b59d586d3ffe2370a872b349057d23b5e86d4b7f6e89129887d9e9a0dc0f6816231962aa7491b6783c080037b97369053b6571812739198446fd2b1cb24e7e39aae5161d88b214eaac85763431b66f1fbd4b96c7f5cf18634b0348e4c0e35ed379b250cbbf17f6e018f81882a45e",
    "8b00154e563a7d74a5f0bd3c2b4cb651aabc68ea1a0eed5ea2614b931231d35c86631b5ad58d450fd30478d2b70df2f45745c019c4aa1973d29506271a16a157a217e37cd6738313b74ffd6bfb3fc2431eb89ae767732a5459eaa0bd08b5e9410cba1970e3838e2fa862963b7cbc7a76",
    "98924872d9253b332c580918a25c2a637e4a0d51e108b9c0c00cc794359f381c489f5567d4009e55d6048812cffc89b753df20b6f83cb5e300c557ba2cc184a7527faed25e9d4d9c8751d34c024bb7f06939df4d185ca942b9fa2d41a60550276cad44d2c8ed9685da451500c3aafa0d",
    "a5a2c00e4406d2c5534348a606f9ed1697ee9b0390faa2792ff2ee40819daaaecb1afa6145f53905e8ecbe800597757e21e1258998d7b0f21222023643080d46328d53653fea2ce74e7a312360e8c8db135d4e6f92a0b86251b9c6877011f6962def69c7a031e3ca070fbead7eb8167b",
    "a0a307e3b2cf6b990e65a2203e6900fbeea67ec6fd1aa87d14c93c39c36c69bd956da30f310c29143876f3b167756c4d10390e92223c00fb14c880bdac8bde6b498d776fdc0fec000ff42d1683fc445d50468ab1f7f849a45bb5a2397f8c6f0d883089691ba402be096294c78626d9d4",
    "880c34047e3256f91c27d8a79aa4420586c547752bbd215d641103cc66cd036864bbd22a28735e43bda0ab463310bedc154f8bbdd3b4b26613387524525b185482a7d0f92366fa08484a26df4def9c251b01ece21d8b141862881748600199a09eb33d5ebdfea9e3cbff9ce846edf555",
    "95835232ce52e6099c196ddbf9f0f57d7d87c718dd790c40955bb2546a3d2760591848f5dc250c720a519d1b9e15bffc70f1586ec50db1fd85c526abc77b0f794a39539b83f6e0d2cac853d0ea80ea47116144529212d2095f85c18d111d4d58bc53546e594f7618d5165ae54b991c20",    
];

const EXPECTED_SIGNATURES_SHA_256: [&str; 7] = [
    "acecb915c1a3505350ef561b058fe8757fe58e0a094e755d759d1211de05773d6b9f463935993e59e52a6a9fc5842b320492cf79b35073e69a4391bcd2ca0fe26aa03b2214fc8f2909b4616c53eecb5f3bebca800d39303caccc5b02cee8db8dd5792d847dd48e2d67d1002813b45abe",
    "ab159d416d42f74cf10a66977f2f63bc4a9c1c35c318590b73824f78bc65f69925307aa14fcded73bcf75d1ecf8807fa070a29084157d88a16fdc138381de337a3222d482181e583864e85a0c3aa2b5c2047c036526e360592d56d7b9c19bb0fb4a9b21e8d2cb12f313bf06738ca5d11",
    "8ab634b51ba9e8a52649b8c271687b047e82716827bf7fbd1b82860bd58ee9d973c296fac2247af199b7998acf9d117921d60800e9cfe4e18f55454a8dc0c0850fa4152a72f3f3c1ddacc2c60b18eceb6c1a3783c187570165e4358778d0ba3b1bda53a0a0cc53e3c840fa7001e917d1",
    "89496cd19f90a92a89cd15ac89b0a7abe8ee4e97871150c83b4f6da1a6cec7d05c107f7ab5176969ebd6947bf421b155442b4435c92001fc591eb801edfad8f9cf8494fca88acbfacda4e115f8b4063b0bd4fe282e21edcfc6fc102839cc6b4df890707985f0f9d3b83d22128c9582dc",
    "9254633117b2d4b7b8e9ba6a422dfea041fde9f04cac010b2c50bfd00e663fd089067083484424ef7b53e83951c90579100a33b6ab7264a8329dc96a386df277c931cebb2a5e5228def0d1682b8137ba52b22b3ed17b6d0b34a052c0e0c6f3ee4e0148f65d9153576626a56614a22dc3",
    "89dc602eff3e922dae14a77615211cfb88f06c979506acc06984f227030e48a724d5b3edebc26a1c4ddfac8bf5a5932b3749061deec26c7879a7c816e25d60753cbdf889b16f7fcaed4b7b4a2bca1ad70e30680d4aa2881f08f2f2987c7ca5643e607ef14e68022c3874b7cce9cc4a58",
    "aa4433d4ad982a4baccee2b5dc987bfa44cd5b507180ef76afef7b58bf699eb93c16835804650a91794692b51ac24b7c00d4abb8ef21923f2ad74333baa8cf2d9bdfd39a717742a351867796390da4df52fc8b43e4c29d1b971e7677fc181c2260f351ac7da3d0d797956a214b3afeb4",    
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

        let result = $proof_gen_fn(&BbsProofGenRequest {
            public_key: &public_key,
            header: Some(header),
            messages: Some(&proof_messages),
            signature: &signature,
            presentation_header: Some(presentation_header),
        });
        assert_eq!(result, Err(Error::SignatureVerification));
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
