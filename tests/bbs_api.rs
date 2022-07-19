use pairing_crypto::{
    bbs::ciphersuites::bls12_381::{
        proof_gen,
        proof_verify,
        sign,
        verify,
        BbsProofGenRequest,
        BbsProofGenRevealMessageRequest,
        BbsProofVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
        KeyPair,
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

const EXPECTED_SIGNATURES: [&str; 7] = [
    "b9bc5ddb6bdbd3b7b60c7e7e57b2dad9c2c0677f94f51e7d9f0df5d446633188058e060b621924cc4393fd63924705815baf10e9234dd953306a295b958902f62052e6a8cf6e6bea9a21781cc37158471504db298ce7e326ce05aa4cb5374c3c74f74f209c8ad7607595c74bc15c9426",
    "89455f50e6ab7cde0684afa49d10f66b8d3545da83a01213b53177ba22d68ca265d4cbb013b003a8598d65b3ca9db7bd0a9d6ecbbffd7ff916fc950e768d85b5efd19c03ac4cb93c95119aa40f8048cf0d30e89180c0617a7d31c0d17e3f85d84eab681b8593448321dd191ef4f45183",
    "b505410652af38a74727227e530a5753ef890d017b86937629c85543e2c1b2c955d5fa1ab1cfd68925041809cd9bf1251d3b6c75a041ae626d740ce576c0668d9487ddab1733eae33e078b10e17535ef490b5ddc5a9b9325f267889c8c2537437f21529c915ecfda11d9d533c88d1ece",
    "8226da54c3d92213cf2a8edfdd7defee7db9d2dbc9158bfd05e14743ad2b93bd0e121758cc1c4e084b1abfbf3f6715da13a5cd1f9ce2a9de80e6b7a6832a6d9d33dd58433c5a9c3e7c24301c4c6cc53e180d11749661b4eefaeead391c5c55833ea751c40c4138cd2ee3a742594f489c",
    "8bda3c7608760bbc4c338c83502668491ede90e9e700f7eddb2720333ba0f220ee48ace2b2356413ba12fd0bac6805ef4ddd2d334176bc02989c0a2f11e630697ef58039b57f5bb4276fc2e14e59e4d6599238729b642a9af5f1e2f59102b30b41cb3fe822e0a7276541f851c5ed398a",
    "a741b26906b6646624b7a6c26f1e2c53a8e18b2d2dd7affe0b8ec1792db8535dc8811f718215a4a08368d25d7e6801a61e997921d4c99cb8dcbbb9a6b0a88b8913779526c8a19d1eaa1efcb390c2cdd907793f148127d175d302e251a5e9beaddc11b5f38578774ee3539e197d2ef67d",
    "8704ecdbd7dee870916a071c694b71b910d1c8bafd446fa5d91e34e58913a1f100d248644f5c4560deb79f9d9f018e271e3863673b52ed37d3f76e898c1e75f2a2f9f0c297c85ce40c56a7a05f8005d313b4b16a59c33fcd583a12f4e7eac94553b6a459e7229b964dbb06e41e585638",
];

const TEST_HEADER: &[u8; 16] = b"some_app_context";

#[test]
fn sign_verify_e2e_nominal() {
    let header = TEST_HEADER.as_ref();
    let messages = &TEST_CLAIMS;

    for i in 0..TEST_KEY_INFOS.len() {
        let (secret_key, public_key) =
            KeyPair::new(KEY_GEN_SEED.as_ref(), TEST_KEY_INFOS[i].as_ref())
                .map(|key_pair| {
                    (
                        key_pair.secret_key.to_bytes(),
                        key_pair.public_key.to_octets(),
                    )
                })
                .expect("key generation failed");

        let signature = sign(&BbsSignRequest {
            secret_key: &secret_key,
            public_key: &public_key,
            header: Some(header),
            messages: Some(messages),
        })
        .expect("signature generation failed");

        let expected_signature =
            hex::decode(EXPECTED_SIGNATURES[i]).expect("hex decoding failed");
        assert_eq!(signature.to_vec(), expected_signature);

        assert_eq!(
            verify(&BbsVerifyRequest {
                public_key: &public_key,
                header: Some(header),
                messages: Some(messages),
                signature: &signature,
            })
            .expect("error during signature verification"),
            true
        );
    }
}

#[test]
fn proof_gen_verify_e2e_nominal() {
    let header = TEST_HEADER.as_ref();
    let presentation_message = TEST_PRESENTATION_MESSAGE.as_ref();
    let messages = &TEST_CLAIMS;

    for i in 0..TEST_KEY_INFOS.len() {
        let (secret_key, public_key) =
            KeyPair::new(KEY_GEN_SEED.as_ref(), TEST_KEY_INFOS[i].as_ref())
                .map(|key_pair| {
                    (
                        key_pair.secret_key.to_bytes(),
                        key_pair.public_key.to_octets(),
                    )
                })
                .expect("key generation failed");

        let signature = sign(&BbsSignRequest {
            secret_key: &secret_key,
            public_key: &public_key,
            header: Some(header),
            messages: Some(messages),
        })
        .expect("signature generation failed");

        assert_eq!(
            verify(&BbsVerifyRequest {
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
            let proof = &proof_gen(&BbsProofGenRequest {
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
                proof_verify(&BbsProofVerifyRequest {
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
}

#[test]
fn proof_gen_failure_message_modified() {
    const NUM_REVEALED_MESSAGES: usize = 4;
    let header = TEST_HEADER.as_ref();
    let presentation_message = TEST_PRESENTATION_MESSAGE.as_ref();
    let messages = &TEST_CLAIMS;

    let (secret_key, public_key) = KeyPair::random(&mut OsRng, &[])
        .map(|key_pair| {
            (
                key_pair.secret_key.to_bytes(),
                key_pair.public_key.to_octets(),
            )
        })
        .expect("key generation failed");

    let signature = sign(&BbsSignRequest {
        secret_key: &secret_key,
        public_key: &public_key,
        header: Some(header),
        messages: Some(messages),
    })
    .expect("signature generation failed");

    assert_eq!(
        verify(&BbsVerifyRequest {
            public_key: &public_key,
            header: Some(header),
            messages: Some(messages),
            signature: &signature,
        })
        .expect("error during signature verification"),
        true
    );

    // Start with all hidden messages
    let mut proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> = messages
        .iter()
        .map(|value| BbsProofGenRevealMessageRequest {
            reveal: false,
            value: value.clone(),
        })
        .collect();

    let mut revealed_msgs = Vec::new();
    for i in 0..NUM_REVEALED_MESSAGES {
        proof_messages[i].reveal = true;
        revealed_msgs.push((i as usize, TEST_CLAIMS[i].to_vec()));
    }

    // Modify one of the messages
    proof_messages[1].value = &[0xA; 50];

    let result = proof_gen(&BbsProofGenRequest {
        public_key: &public_key,
        header: Some(header),
        messages: Some(&proof_messages),
        signature: &signature,
        presentation_message: Some(presentation_message),
    });
    assert_eq!(result, Err(Error::SignatureVerification));
}
