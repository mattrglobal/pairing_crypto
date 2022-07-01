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

const TEST_PRESENTATION_MESSAGE: &[u8; 20] = b"e8gxekZpmeZTU0VDL9MV";

const EXPECTED_SIGS: [&str; 7] = [
    "aeac37f08d62876ae01c0d3b244d9f457b74f928271aa84ebf730982b0d7f9e622aba85f4aec54f90714ffea69839b2c7011777eb4e89ca0cbbe7d25cc025d40bdcc15efbccd02ab25561589fc0d01c01fbd3fc8247b1a0105f5caa5fdb7c95ca2fa0ab08eeb09af048f9462a1ec5d8d",
    "84e7ecd45f36e6eaad8863b79c290843271dbfbfc64f95288772b8999e7054248dacd2e50ec558659a66a9fbebdebfeb383f2f6f6eb960cb2ec7dc43991ed7d00c1aef095687000246f874cec690a3114787dfa98316d0bf13697d6a6d212b5d9d67bf6f390d1c24ee9daaefddeeadd5",
    "8ea7aa0b96923c6bdee49cb507ca5feafa98145103dfb1f6fc67e9fd300d4ac49b635063482631ccc936ba0b549497fa17860d41f01e7393306691d61e895d5090d71a0e223c04de9d4f0c8054d1d8d90f24abcc2bf1fb5ba92af73ecae6fb2daa7087fda4c391e67fdbdcd46bb8ecb8",
    "a8ea0f9fda19b21c0e71f70d01e5d6305f2df015fb97f1045d31ddea345cfcdd6f0ebd49a6a2ba5a76be257e68bffa4b5c862e5d2252fc88c0942f9f44823be3580f96104d942d1ca691ea02f42943c836e0f2a5c133e6444aa7469604dd7f134d2d91bf21545c4baee107898246e9c1",
    "b25147bb7e6eb43dca2066ba3d910a222c0f7f9f18b3720b21216b323a5f76bd52bd0957e03dcccc7d688809d5e7cf56345973b8a25054de9d27c8479d94b036c8716a41df4afb8c8828e4e98b1cd4f434a1dd6407ee6c821bc8dc2bec46884d58177f31abb4f0d3d281ce6daa086946",
    "b731a37212e78df0bfccfc8cad90c8e2716c670078676bb99d8863e5d7c24ede6dd6fd91b4120ab572148309c7639814627cbfe1d73960d5833bd04234d32f95ea40aeae5747e521a740058c50436ecf2bfff6fbc5206be7b0a08930ab432935882a7056fea3a52f8a3d99cdedf6edbb",
    "a93dda896920660b9803cc880741e5c4f35609d18483e380016d3487d1bca9aefd782ba5853860f6f694957ee4dfd4a400a2ec0604a40089cae1f82d04277a8a2f32f8441b3c8e8d0958b29de38643c0547fa636902790b358c58d28c4db94a2cccbba074fd58123b3dbf488337dd707",
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
            hex::decode(EXPECTED_SIGS[i]).expect("hex decoding failed");
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
