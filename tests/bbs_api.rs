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

const TEST_PRESENTATION_MESSAGE: &[u8; 25] = b"test-presentation-message";

const EXPECTED_SIGNATURES_SHAKE_256: [&str; 7] = [
    "b9bc5ddb6bdbd3b7b60c7e7e57b2dad9c2c0677f94f51e7d9f0df5d446633188058e060b621924cc4393fd63924705815baf10e9234dd953306a295b958902f62052e6a8cf6e6bea9a21781cc37158471504db298ce7e326ce05aa4cb5374c3c74f74f209c8ad7607595c74bc15c9426",
    "89455f50e6ab7cde0684afa49d10f66b8d3545da83a01213b53177ba22d68ca265d4cbb013b003a8598d65b3ca9db7bd0a9d6ecbbffd7ff916fc950e768d85b5efd19c03ac4cb93c95119aa40f8048cf0d30e89180c0617a7d31c0d17e3f85d84eab681b8593448321dd191ef4f45183",
    "b505410652af38a74727227e530a5753ef890d017b86937629c85543e2c1b2c955d5fa1ab1cfd68925041809cd9bf1251d3b6c75a041ae626d740ce576c0668d9487ddab1733eae33e078b10e17535ef490b5ddc5a9b9325f267889c8c2537437f21529c915ecfda11d9d533c88d1ece",
    "8226da54c3d92213cf2a8edfdd7defee7db9d2dbc9158bfd05e14743ad2b93bd0e121758cc1c4e084b1abfbf3f6715da13a5cd1f9ce2a9de80e6b7a6832a6d9d33dd58433c5a9c3e7c24301c4c6cc53e180d11749661b4eefaeead391c5c55833ea751c40c4138cd2ee3a742594f489c",
    "8bda3c7608760bbc4c338c83502668491ede90e9e700f7eddb2720333ba0f220ee48ace2b2356413ba12fd0bac6805ef4ddd2d334176bc02989c0a2f11e630697ef58039b57f5bb4276fc2e14e59e4d6599238729b642a9af5f1e2f59102b30b41cb3fe822e0a7276541f851c5ed398a",
    "a741b26906b6646624b7a6c26f1e2c53a8e18b2d2dd7affe0b8ec1792db8535dc8811f718215a4a08368d25d7e6801a61e997921d4c99cb8dcbbb9a6b0a88b8913779526c8a19d1eaa1efcb390c2cdd907793f148127d175d302e251a5e9beaddc11b5f38578774ee3539e197d2ef67d",
    "8704ecdbd7dee870916a071c694b71b910d1c8bafd446fa5d91e34e58913a1f100d248644f5c4560deb79f9d9f018e271e3863673b52ed37d3f76e898c1e75f2a2f9f0c297c85ce40c56a7a05f8005d313b4b16a59c33fcd583a12f4e7eac94553b6a459e7229b964dbb06e41e585638",
];

const EXPECTED_SIGNATURES_SHA_256: [&str; 7] = [
    "857258e3f8afcc4b527672df865cbb2f7ae38a7883c8a1ddd2f1b396ad9e5b0b09b432c0c053524d38d45e1197c354a56647b3518d203773209690db025bbcbf4039d7496723bff03f04ae9cdc0125c768c8080ff7fd6600158973b297ff79cd741dff65dbcbfa4840b260c4276d887e",
    "b42136d7428d367c6140097a1b310e4fd5645fbe5693f840fcbe1ce49419c03cbe21ee014420c44ccbd91c86bc660cc846e03698953000bb0be5758e776b837fafabba001d7402690bd9e90424fc55b309cb1562347b9d0eac0c5f4b96c785f8ca5727ebd9d743d9939bbf603bed7386",
    "89163ea7b47af2593da764bd1feb82cb8fdf61f818dea9f37392beaba0d73a6aef882a3a25cf484dd2fae6e20f8ab75b6e598458eb3624b27718cc4b5b704be834491e799106bdfbbc1b03cadd29e90957931050c3053d4761e3a5478337173ab41770120ab8e5047e844b7ab37a3ba9",
    "b25137f793b13843b39505ead13e068d289357a89c9e7df83e6c9d70f9ed8416ee066587a23874fa9c334f675deaa203056382470679d7df438fa36094b20bb8cbdcbc74012f3c76cf16cdd4f3f3f5f2177bb9bb706bdaebf41bf1c6004ff4ac4a59fee89e0d043ae93e1f22f6d31b47",
    "96f06552de8cade500138279fddd856bc438ec7d9e9efbec45ad85d4b0b9cdf1e87f79bc3d156213821249c3a6cf999f2b7f519486abc034a4c5b66f82b1b9cb3bfadf7ea9d22b28b31c114c5028e0cc66e9e83d59e050cd9c31436832a96095e055432c85205702e5b9b879bcea6628",
    "a267e8040945448a1089b11b8dd4a573589a973d52ced0b77fc74c0c8f01e7c1c3feb9a4c2041d7cd3e28810fad69bbe249fd090495bedbf8ef7a021b9f7419f6cd82dab15c263a605436bae9862ae3141b575055d0c333abbc43f253fd1595162cbbee97fea8cc5fa199e578153d8e8",
    "aee499750676ef8cddbcc97de16fe6f80a5aa7721c217d87f292bffb9ebb7eb10015de56236c1a08307c08ee8fb46e1647e9aa2cd9dacd766ff680e6232b8726e3aa9891492312c2f382617bdec2f9d8298ddf71f5f7a0ee1e0454a7cceb458593424d0a0347feba80afe5da1414393a",
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
        let presentation_message = TEST_PRESENTATION_MESSAGE.as_ref();
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
                    presentation_message: Some(presentation_message),
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
                        presentation_message: Some(presentation_message),
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
        let presentation_message = TEST_PRESENTATION_MESSAGE.as_ref();
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
            presentation_message: Some(presentation_message),
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
