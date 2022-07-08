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
    "881624ee88e1bb10787c1d6c7d2bf45a108aed8914c2b5142297d01135edd2e9a18b67d53a565758bce7809e967c94016d04c9ce3256ff347ed656343e81cfb515fc75f88de1fc2c9427765576ad5b243199c0b196d14fb7fb09f51e7af933989f6d8b6bb03bb14e833117776cda8a7f",
    "a380e48ae0b273b9e8ec478fa92090b661611f785d1504c52e6842f61c57be84570cb2593ea410b6b56a685686b3eae435b3d0414bc9a8ebd3544774f444645a59ec98c2f4e8eb9522cdeea639d97bc060f4810f759803a8d6d2e30a4819cf5fe169e5ca453fa65b6119093134db6f8b",
    "b16ed331c572b248afb8546bb6f6a38beef2dc0c58726d1b966a2186da4e92f26673edd86e2c159ed53ec73c502a08f672ebb384d94055ab615daa3c02b003c6449734d39a22b90a648d87295590514a5b841d95570dadad60e138ce669594bdbdbfe078ee6e15958404454c8aa9f17e",
    "af1f1b37290101cb445acd9d49b7ff586a23f1f012cfe54d67ff01e806e1b49db25a25886463387bf2cd9ef98eed93e14b299c0e65d89e91620d478277619043f126f04488867d145da7b61821276a9701c1740b1b05082d823fb0b826bbcd4de0ba540a6bd879d75978a50c7449fd85",
    "b55f1ade8b55b258f1c155bd4d97848a1a85ed5d1f20f6a11e290979daecb81d825a1e8e017f9cf2919348d2e7a0d9466a925de1f242a68f58653c24025d243c82536a7d56dc5884cb5f62937e57a58e2c5b6febe2631153f758e334560cd8acefd801b7929d84737c705f9043b9d4b7",
    "807345840862b1c5ee8b7d087b48a7b811f06d0a1a504c8bf4b1823f730244028c697781ee5ddca60b5de4cc674c62b34e06fb88d4105adc0a37fdb5c2f0e33b8c34e138ef83b6a8774e558cc799f2363cb89c770908de677484000bd779f2c9c4397762ca7c32d798b4188c7ccb5840",
    "a1845b57f423d642747064879a725a74a795af2d82fe8f1f20d7693267162f58579ead1872f2b4572c047a5b7d57ffa057ba8ac7ec22a27301b94b149a5cecb3e70ffa42d3a812da5df00015584cd9bc63004b90620dcad02ff1ddd23ccc520fac4e3b4dab6bcdfcb69843e230d98573",
];

const TEST_HEADER: &[u8; 16] = b"some_app_context";

#[test]
fn sign_verify_e2e_nominal() {
    let messages = &TEST_CLAIMS
        .iter()
        .map(|&e| e.to_vec())
        .collect::<Vec<Vec<u8>>>();

    for i in 0..TEST_KEY_INFOS.len() {
        let (secret_key, public_key) =
            KeyPair::new(KEY_GEN_SEED.as_ref(), TEST_KEY_INFOS[i].as_ref())
                .map(|key_pair| {
                    (
                        key_pair.secret_key.to_bytes().to_vec(),
                        key_pair.public_key.point_to_octets().to_vec(),
                    )
                })
                .expect("key generation failed");

        let signature = sign(BbsSignRequest {
            secret_key,
            public_key: public_key.clone(),
            header: Some(TEST_HEADER.to_vec()),
            messages: Some(messages.to_vec()),
        })
        .expect("signature generation failed");

        let expected_signature =
            hex::decode(EXPECTED_SIGNATURES[i]).expect("hex decoding failed");
        assert_eq!(signature.to_vec(), expected_signature);

        assert_eq!(
            verify(BbsVerifyRequest {
                public_key,
                header: Some(TEST_HEADER.to_vec()),
                messages: Some(messages.to_vec()),
                signature: signature.to_vec(),
            })
            .expect("error during signature verification"),
            true
        );
    }
}

#[test]
fn proof_gen_verify_e2e_nominal() {
    let messages = &TEST_CLAIMS
        .iter()
        .map(|&e| e.to_vec())
        .collect::<Vec<Vec<u8>>>();

    for i in 0..TEST_KEY_INFOS.len() {
        let (secret_key, public_key) =
            KeyPair::new(KEY_GEN_SEED.as_ref(), TEST_KEY_INFOS[i].as_ref())
                .map(|key_pair| {
                    (
                        key_pair.secret_key.to_bytes().to_vec(),
                        key_pair.public_key.point_to_octets().to_vec(),
                    )
                })
                .expect("key generation failed");

        let signature = sign(BbsSignRequest {
            secret_key: secret_key.clone(),
            public_key: public_key.clone(),
            header: Some(TEST_HEADER.to_vec()),
            messages: Some(messages.clone()),
        })
        .expect("signature generation failed");

        assert_eq!(
            verify(BbsVerifyRequest {
                public_key: public_key.clone(),
                header: Some(TEST_HEADER.to_vec()),
                messages: Some(messages.clone()),
                signature: signature.to_vec(),
            })
            .expect("error during signature verification"),
            true
        );

        // Start with all hidden messages
        let mut proof_messages: Vec<BbsProofGenRevealMessageRequest> = messages
            .iter()
            .map(|value| BbsProofGenRevealMessageRequest {
                reveal: false,
                value: value.clone(),
            })
            .collect();

        // Reveal 1 message at a time
        for j in 0..proof_messages.len() {
            let proof = &proof_gen(BbsProofGenRequest {
                public_key: public_key.clone(),
                header: Some(TEST_HEADER.to_vec()),
                messages: Some(proof_messages.clone()),
                signature: signature.to_vec(),
                presentation_message: Some(TEST_PRESENTATION_MESSAGE.to_vec()),
            })
            .expect("proof generation failed");

            let mut revealed_msgs = Vec::new();
            for k in 0..j {
                revealed_msgs.push((k as usize, TEST_CLAIMS[k].to_vec()));
            }

            assert_eq!(
                proof_verify(BbsProofVerifyRequest {
                    public_key: public_key.clone(),
                    header: Some(TEST_HEADER.to_vec()),
                    presentation_message: Some(
                        TEST_PRESENTATION_MESSAGE.to_vec()
                    ),
                    proof: proof.clone(),
                    total_message_count: messages.len(),
                    messages: Some(revealed_msgs.as_slice().to_vec()),
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
    let messages = &TEST_CLAIMS
        .iter()
        .map(|&e| e.to_vec())
        .collect::<Vec<Vec<u8>>>();

    let (secret_key, public_key) = KeyPair::random(&mut OsRng, &[])
        .map(|key_pair| {
            (
                key_pair.secret_key.to_bytes().to_vec(),
                key_pair.public_key.point_to_octets().to_vec(),
            )
        })
        .expect("key generation failed");

    let signature = sign(BbsSignRequest {
        secret_key: secret_key.clone(),
        public_key: public_key.clone(),
        header: Some(TEST_HEADER.to_vec()),
        messages: Some(messages.clone()),
    })
    .expect("signature generation failed");

    assert_eq!(
        verify(BbsVerifyRequest {
            public_key: public_key.clone(),
            header: Some(TEST_HEADER.to_vec()),
            messages: Some(messages.clone()),
            signature: signature.to_vec(),
        })
        .expect("error during signature verification"),
        true
    );

    // Start with all hidden messages
    let mut proof_messages: Vec<BbsProofGenRevealMessageRequest> = messages
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
    proof_messages[1].value[1] = 5u8;

    let result = proof_gen(BbsProofGenRequest {
        public_key: public_key.clone(),
        header: Some(TEST_HEADER.to_vec()),
        messages: Some(proof_messages.clone()),
        signature: signature.to_vec(),
        presentation_message: Some(TEST_PRESENTATION_MESSAGE.to_vec()),
    });
    assert_eq!(result, Err(Error::SignatureVerification));
}
