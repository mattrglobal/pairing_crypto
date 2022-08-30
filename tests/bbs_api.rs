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
    "b9a53813dd344dd8baf51695f7af2aef330b2c2fcb40c5ea213e91d5ea3efb41128cc9613a87a8c07e17d38091f3d9ba0a960e9ff7aa84b137689f7cd2ba8e9ee4fab6046dd8cf18efc91b905832423e099bb67bcff3cc2b44737f039a280728fbb8930b47cd7ab8682c8ed1c9906572",
    "9592ee0d1d4a977b4dc93815fe0bb9275b19b66f1685a6f4eefb527229cbd45cfdcd00504a09bf7d49a6d60e503d978c477af1ef012fa05febb886cdf530e616e835b05e7ed05631686b5556aac933b7140c4137abfcfd89f40bfed35437e342ca21b93b07a83b76edccade251f9b6d2",
    "9413ea234382535188323d0fef35c500eb534ed66ca42171636ef31ba67bdc9890599e7a54686f9a41ab8c0cb2fec5c64268a60ad8fa9f0eb47e6f2b68b457b4d2c188e7b87429e758c8b1a4efa4d0b532d7a435e1cf77e64f058e63bc5e468fbe3342ae48636998aca71bf9d1d9ab1a",
    "ac7a8b3c0e4d03fe63752e460063e98b6228b430e6faa0194c58ed578a4c492a78b69a37624d35e661bacee4a6c7657b70b5b738a192bbf09c7dad954a7846897eb069d52e80bd75ca2c2be78a43f35e3e44d51ae83d6fc1642729339ddd2ca1deac42998055e4f4c7537deee2d9450c",
    "875221d857a0231bf9257f8f82306fc2c87dd02609a54a84f795c13cac00d24dbf748bc2efce3c8dfdd4c0b0b84eb1d2509302ac96736043cef3a55ec7eed0352c2811760da222b515e42064fe904d7e27a9d097f0822c1568afa8055c51765bad226d844929f15c5f4a645f8ed2897d",
    "86fd52f3c41584a2847bf9d0a4c8e475f09ee190c1a9e7e95152dcfdd66d3376ff08bbfaf7336c3eb6367dff088b11461d85e63066ab1c739c536a076bb90777eaed0bea1c50d011a974a89a3f52fc674e0970e5b3ed5a16a9c1d35378173017ea2d11b617da7333d714220e43768a68",
    "845463d7addd3e3967411b26eb6afee4e9c3707b7ee9348c7bae205cf096cbb5589f90f6b79abe40127896c5d27ac4056d344b53e9399f35bb0d8c48f2250c9930da1dd21597c14181b46efe361271a0435c234e2feb4e496fa46184aaa073ed4b438877d57d36c84841c3dfcc419fb7"
];

const EXPECTED_SIGNATURES_SHA_256: [&str; 7] = [
    "b7e760462f57047eb2e0cc628c4d361ba96ff2d36f33644f5b639793ddf676add5c33fc8a4366b4f9ef8ef74357055392eae1ac084be9dc42783d793f7d577a0277ae915ce14a82a1d30ae30411b264f52546d9dde3fa3a0313be9fc97b11e94d371bd3a3cc82ccf9df7d9ac046f0d21",
    "ab344b063d3c3e468590e3184c8a5855b52fc241b7df8f370a19414d33101620e281acd386d6ec076f6f77d28d2ffe5b6452c3672f953522887ea68ce6875e653353391399dc1eecc4ede3ac0a519c1d405f26c1ef35a02a8ba7997bc0afc8b41195092b56c632a8232518a49a2d638e",
    "810aa13adcd2af70782caa48578fa60a24677e9fe82d3083ea7e5415d5bc9cd4340e378ba09cf8d62f2599fd8b2a7d3119ab917119ce0236d7c0cb6823c95a51ff784c51ca5ba700417a98ec60bf5a71381133f641c643902bce317d813af97f7fe28f1c48010f1874585e60cfca4768",
    "b3f2c93894410a5ce8c37ffd32e3a5e79632888f33943ccfc55331e353b31e511dd1c8a075f5aa55a956aba26139cc35449083d32dfb09a8115130e527d7deae5550cc1a445cdec2c7f4832b89aa36a91077b85ce2e6f3f7df501b39480a96c15c153b8fca0ae4c1e8672a14be5bd2fd",
    "9220d9a44c3df5f58833d643f5d6cd3f61eed7584872b4c57bb179b72819096939735be8193de33423bfc93512a62a4a233132c87b5fccedb2ce0ee9c52013f2969b28ba7d87d7d8c23df4c92e855bba1ff1ee21af7af1e773373fdb6db17ea789e111492f70ab5d3957236b2f42ae63",
    "a2249f0fb9a62a13124095674f844cd3e596155bcbe3c5a5d98f3703ec896dce4da27a470104e57d509102ad6fbe1d18222bf2813930e0b067bf32a30e91f574cec03e83a4cd4dae2ecca9d6361f1fa81d4005598c93b0181613e6146a4054bc5001851e0779e518d6daed5c40758dce",
    "89c491f803802dc943b9c8a8623a5bc1505c44879308f0a8cb6de8627db4737fb651a17f74f6516d360b0dc2475d81cf28bf792a0ee04a80302fe5991f5a420786a55b4eb6211c37f9fc7f2fd5fac7b171e68e2135c97d431325826e162fcc62bc5230dff1beca26e49a4aaf378de1e2",
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
