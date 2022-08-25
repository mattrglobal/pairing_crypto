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
    "b6686e89636673c3f52d67dd39f0b39fbc7b82b4e7897bda124329a8e47efe27c984c775907c89cb34424b6a56dec2885f7c7bb68ed9c7bc06beaad407aa91b9dde1857355daf185b2d5e087d0fb966925cbeab0e69dbb58d0583383a1aafbd132129d4bde7521b35f9f459c36dd18aa",
    "b63fd2b7b7d092af3f1b1656d60a4415c3990f9de122a023a71ca941d72ac88c734f8804f5ef23e3a0f25d77e5e0669073cdc2955b18ce5b72d6961fb7671aa57ddb40ef9bf397aa21b5a4de0dd3a3cd24bf3f9a479960493d0493fa6eaf0d06488d7c858811e4d920ff4c7b5e7dfeb7",
    "a310d46e9ecad20c5cff4050cbe8066c93cf33496839b27eb1b8cbb91b4aac9b3e6cf6c3710097b4dfcc8208c2e775f21529099064d6a5169cdedeb03d3493ba41cdfbea998badcb2439076eca203803048760afcdf3c48098f8565070fdc504f2bcb56bb9ee8b1880be6225ebd292f7",
    "967b60f0f42f3017872521dbc133a99d530c8db274ad9bcfb6153a7fcb5e5b587d894cca9af3b1154fbc9d62ff09b2d33d85d0b49dd22e1f63fec5a508f97cc20bbf9aa943d2b0822ab053ac402387be0875705bdd57b95318d26676bad910f445f02e40e9f146b3ddb8c06898a41a3f",
    "a88f1503840d4a22d142b182083a4cb1ab54d40e8ceb9410958cf0804089aeb8f335728f635aa17a3ccb4d70d8bfe4774b1859b4667674e3821d00a7c40abf4b0837cc39bd3fa7faeccdc866b3bc1e6f38ee44b80aaf66db2b2bd0f1f23d5123f44bc6d4d2fddf6cf797c05165d36f3b",
    "983bcc97b3d37e2718a344f8c140b3bf7d744cb2de20c2a8b372f0f5e6e8ac0fcc5ad4fe3057e50c0525117d2a8fefba664c4035a11f85c291257596616ec600e02a7b76a7a0d5a31d880ad9ac69017f398232378a3488c9c1d9b2a2e3e74bee57237a05c8faf9c84696fecc3f58bd31",
    "a27cd6d07201615c8ea146d8237d5d193a3a4e9fb0cb8ce48f418a49f617da3db73a85bf86c29b3950dacd7566161cfd10e0f9353eb1642097dc08c522efc23886fd3b902bc4b58a8ace9acdeda472cb51d7302f3ea7f1a9eb05b54eea17c501d54cadca633de6a524522b22629947b6",    
];

const EXPECTED_SIGNATURES_SHA_256: [&str; 7] = [
    "86d3cb01e4f4c09b150b06eda48996ed65617af447ceb1a98a28038177b46e47d478d369c3fc4b04de9039d6fb44bf14151311711644a398bd76fbb0178573f128de36c711590dc85bf0c70e4b7c97aa33d4689b029eac69b9116e8e4de397919597a377117f55d2012d4e7c218f8126",
    "afd9d43f90d9473c891442a79adecd26139265c2469453113b0c9dec2261fcfd9926215d36362a57ef5a078f96c359de4a89a47d127a61252ff2caa2dbc826671e496b1455e1b9e121c4e57a1b33f77622b806af0c8b6259224eb9334a09ac9f58f12e9f42eb4be2b47c9bd9d9a5b44b",
    "b7ac235e1dc1d1fc82e6cc4eb099c9ab08795402f29ba1866f89e0576c6f153bdfff8d386af3a70e5f1b47d3278d23da46ad22b6fe619cef731c78cd3cfa6fcd05ee5afe4ee82f05664db896e1b013fc6dc2c4c7b834fa086dcc823cc8397d5983836ff55ee90cbd8466017c5b7c0bb2",
    "91ee72bf9e97fde0b3fc301ce81b80769268f05fe324ea5bc15a1fb1b8dbaed7ef316a75692e73438cc346817358b0761cf724f24df8471e282e80eb72ffe030bea6acc20c3fd67198beba32e60cf77c6934f15bfdbbfa6b13e27a125237d5162597d5b5879c2cb359d7c4a66e1aada0",
    "a33d50e9beda2451d08965690148a97f24609bf14e919cafdd29c509c79458a9e260e7e4bea86c7065278616015c127a25f90f1412258bda5d4722fdadf998d7f1c54e3f5cc19ad2a15df5b6f5bb38c0669876295398b0012941a7e39360ad8ab1aebda15a5f71474ce3694ca099ef19",
    "a08ef373a6455c69c93e1ba000feb0794e8f251b9cd6f22c8b854c302fedeef764eeb74cdb227d6a6e55ccfd4c81aac109418b8bed29d39d804e10e3ff65ae988025c4af5a65edec001939a0095534e24fdd5adba785440b168676607d4c2ff63c62be65896f2dd3b179fcf0283b61d8",
    "87fcddd1eed3be04f9feb8ed67beee01974e9b7d50c88baf9ca94ba94fad69792b3bd053ae80a98fdba6874f2ef6bb764d6950b7360175616387ce2176614df566e8926af34a028f0a558bf5d16d212f436ecb17198ef23b092540f1fcfdb0acdfc36f459822079ef8ea35d51224f753",
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
