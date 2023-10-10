use crate::{
    bbs::{
        ciphersuites::bls12_381_g1_shake_256::Bls12381Shake256CipherSuiteParameter,
        core::{
            generator::{
                memory_cached_generator::MemoryCachedGenerators,
                Generators,
            },
            key_pair::{KeyPair, PublicKey},
            proof::Proof,
            signature::Signature,
            types::{Challenge, FiatShamirProof, Message},
        },
    },
    curves::bls12_381::{
        G1Projective,
        Scalar,
        OCTET_POINT_G1_LENGTH,
        OCTET_SCALAR_LENGTH,
    },
    tests::bbs::{
        create_generators_helper,
        get_random_test_key_pair,
        get_random_test_messages,
        proof::test_helper,
        test_generators_random_message_generators,
        test_generators_random_q,
        ANOTHER_TEST_HEADER,
        TEST_HEADER,
        TEST_PRESENTATION_HEADER_1,
        TEST_PRESENTATION_HEADER_2,
    },
    Error,
};
use ff::Field;
use group::{Curve, Group};
use rand_core::OsRng;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn test_data_proof_gen_verify_valid_cases() -> [(
    (
        KeyPair,
        Option<&'static [u8]>,
        Option<&'static [u8]>,
        MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter>,
        Vec<Message>,
    ),
    &'static str,
); 4] {
    const NUM_MESSAGES: usize = 5;
    let key_pair = get_random_test_key_pair();
    let header = Some(TEST_HEADER.as_ref());
    let ph = Some(TEST_PRESENTATION_HEADER_1.as_ref());
    let messages = get_random_test_messages(NUM_MESSAGES);
    let generators = create_generators_helper(messages.len());

    [
        (
            (
                key_pair.clone(),
                None,
                None,
                generators.clone(),
                messages.clone(),
            ),
            "no header, no presentation-header, and equal no. of messages and \
             message-generators are provided",
        ),
        (
            (
                key_pair.clone(),
                header,
                None,
                generators.clone(),
                messages.clone(),
            ),
            "valid header, no presentation-header, no messages and no \
             message-generators are provided",
        ),
        (
            (
                key_pair.clone(),
                None,
                ph,
                generators.clone(),
                messages.clone(),
            ),
            "no header, valid presentation-header, and equal no. of messages \
             and message-generators are provided",
        ),
        (
            (
                key_pair.clone(),
                header,
                ph,
                generators.clone(),
                messages.clone(),
            ),
            "valid header, valid presentation-header, no messages and no \
             message-generators are provided",
        ),
    ]
}

pub(crate) fn test_data_proof_gen_invalid_parameters() -> [(
    (
        PublicKey,
        Signature,
        Option<&'static [u8]>,
        Option<&'static [u8]>,
        MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter>,
        Vec<Message>,
        BTreeSet<usize>,
    ),
    Error,
    &'static str,
); 17] {
    const NUM_MESSAGES: usize = 5;
    let key_pair = get_random_test_key_pair();
    let header = Some(TEST_HEADER.as_ref());
    let ph = Some(TEST_PRESENTATION_HEADER_1.as_ref());
    let messages = get_random_test_messages(NUM_MESSAGES);
    let generators = create_generators_helper(messages.len());
    let indices_all_hidden = BTreeSet::<usize>::new();
    let signature =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            header,
            &generators,
            messages.clone(),
        )
        .expect("signing failed");

    [
        (
            (
                key_pair.public_key,
                signature,
                None,
                None,
                create_generators_helper(0),
                vec![],
                indices_all_hidden.clone(),
            ),
            Error::BadParams {
                cause: "nothing to prove".to_owned(),
            },
            "no header, no presentation-header, no messages, no \
             message-generators",
        ),
        (
            (
                key_pair.public_key,
                signature,
                None,
                None,
                generators.clone(),
                vec![],
                indices_all_hidden.clone(),
            ),
            Error::BadParams {
                cause: "nothing to prove".to_owned(),
            },
            "no header, no presentation-header, no messages but \
             message-generators are provided",
        ),
        (
            (
                key_pair.public_key,
                signature,
                None,
                None,
                create_generators_helper(0),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: 0,
                messages: messages.len(),
            },
            "no header, no presentation-header, no message-generators but \
             messages are provided",
        ),
        (
            (
                key_pair.public_key,
                signature,
                None,
                None,
                generators.clone(),
                vec![Message::random(&mut OsRng); 2],
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: 2,
            },
            "no header, no presentation-header, more message-generators than \
             messages",
        ),
        (
            (
                key_pair.public_key,
                signature,
                None,
                None,
                create_generators_helper(NUM_MESSAGES - 1),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: 4,
                messages: messages.len(),
            },
            "no header, no presentation-header, more messages than \
             message-generators",
        ),
        (
            (
                key_pair.public_key,
                signature,
                None,
                ph,
                generators.clone(),
                vec![],
                indices_all_hidden.clone(),
            ),
            Error::BadParams {
                cause: "nothing to prove".to_owned(),
            },
            "no header, valid presentation-header, no messages but \
             message-generators are provided",
        ),
        (
            (
                key_pair.public_key,
                signature,
                None,
                ph,
                create_generators_helper(0),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: 0,
                messages: messages.len(),
            },
            "no header, valid presentation-header, no message-generators but \
             messages are provided",
        ),
        (
            (
                key_pair.public_key,
                signature,
                None,
                ph,
                generators.clone(),
                vec![Message::random(&mut OsRng); 2],
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: 2,
            },
            "no header, valid presentation-header, more message-generators \
             than messages",
        ),
        (
            (
                key_pair.public_key,
                signature,
                None,
                ph,
                create_generators_helper(NUM_MESSAGES - 1),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: 4,
                messages: messages.len(),
            },
            "no header, valid presentation-header, more messages than \
             message-generators",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                None,
                create_generators_helper(0),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: 0,
                messages: messages.len(),
            },
            "valid header, no presentation-header, no message-generators but \
             messages are provided",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                None,
                generators.clone(),
                vec![],
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: 0,
            },
            "valid header, no presentation-header, no messages but \
             message-generators are provided",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                None,
                generators.clone(),
                vec![Message::random(&mut OsRng); 2],
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: 2,
            },
            "valid header, no presentation-header, more message-generators \
             than messages",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                None,
                create_generators_helper(NUM_MESSAGES - 1),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: 4,
                messages: messages.len(),
            },
            "valid header, no presentation-header, more messages than \
             message-generators",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                create_generators_helper(0),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: 0,
                messages: messages.len(),
            },
            "valid header, valid presentation-header, no message-generators \
             but messages are provided",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                vec![],
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: 0,
            },
            "valid header, valid presentation-header, no messages but \
             message-generators are provided",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                vec![Message::random(&mut OsRng); 2],
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: 2,
            },
            "valid header, valid presentation-header, more message-generators \
             than messages",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                create_generators_helper(NUM_MESSAGES - 1),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            Error::MessageGeneratorsLengthMismatch {
                generators: 4,
                messages: messages.len(),
            },
            "valid header, valid presentation-header, more messages than \
             message-generators",
        ),
    ]
}

pub(crate) fn test_data_proof_uniqueness() -> [(
    (
        PublicKey,
        Signature,
        Option<&'static [u8]>,
        Option<&'static [u8]>,
        MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter>,
        Vec<Message>,
        BTreeSet<usize>,
    ),
    (
        PublicKey,
        Signature,
        Option<&'static [u8]>,
        Option<&'static [u8]>,
        MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter>,
        Vec<Message>,
        BTreeSet<usize>,
    ),
    &'static str,
); 9] {
    const NUM_MESSAGES: usize = 5;
    let key_pair = get_random_test_key_pair();
    let key_pair2 = get_random_test_key_pair();
    let header = Some(TEST_HEADER.as_ref());
    let header2 = Some(ANOTHER_TEST_HEADER.as_ref());
    let ph = Some(TEST_PRESENTATION_HEADER_1.as_ref());
    let ph2 = Some(TEST_PRESENTATION_HEADER_2.as_ref());
    let messages = get_random_test_messages(NUM_MESSAGES);
    let messages2 = get_random_test_messages(NUM_MESSAGES);
    let generators = create_generators_helper(messages.len());
    let generators_different_message_generators =
        test_generators_random_message_generators(messages.len());

    let indices: Vec<usize> = (0..NUM_MESSAGES).collect();
    let indices_all_hidden = BTreeSet::<usize>::new();
    let indices_all_revealed =
        indices.iter().cloned().collect::<BTreeSet<usize>>();
    let first_and_last_indices_revealed = [0, NUM_MESSAGES - 1]
        .iter()
        .cloned()
        .collect::<BTreeSet<usize>>();
    let signature =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            header,
            &generators,
            messages.clone(),
        )
        .expect("signing failed");
    let signature_with_different_key_pair =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair2.secret_key,
            &key_pair2.public_key,
            header,
            &generators,
            messages.clone(),
        )
        .expect("signing failed");

    // The test data for a pairs of proofs generation, values vary in a single
    // input parameter of `Proof::new(..)` which has 6 input paramters.
    [
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            (
                key_pair2.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            "public keys differ",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            (
                key_pair.public_key,
                signature_with_different_key_pair,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            "signatures differ, generated with different key-pair",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            (
                key_pair.public_key,
                signature,
                header2,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            "headers differ",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            (
                key_pair.public_key,
                signature,
                header,
                ph2,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            "presentation headers differ",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators_different_message_generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            "message-generators differ",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages2,
                indices_all_hidden.clone(),
            ),
            "messages differ",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_revealed.clone(),
            ),
            "revealed indices differ - all hidden vs all revealed",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_hidden.clone(),
            ),
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                first_and_last_indices_revealed.clone(),
            ),
            "revealed indices differ, all hidden vs first and last revealed",
        ),
        (
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                indices_all_revealed.clone(),
            ),
            (
                key_pair.public_key,
                signature,
                header,
                ph,
                generators.clone(),
                messages.clone(),
                first_and_last_indices_revealed.clone(),
            ),
            "revealed indices differ, all revealed vs first and last revealed",
        ),
    ]
}

pub(crate) fn test_data_proof_verify_invalid_parameters() -> [(
    (
        Proof,
        PublicKey,
        Option<&'static [u8]>,
        Option<&'static [u8]>,
        MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter>,
        BTreeMap<usize, Message>,
    ),
    Error,
    &'static str,
); 9] {
    const NUM_MESSAGES: usize = 5;
    let key_pair = get_random_test_key_pair();
    let header = Some(TEST_HEADER.as_ref());
    let ph = Some(TEST_PRESENTATION_HEADER_1.as_ref());
    let messages = get_random_test_messages(NUM_MESSAGES);
    let generators = create_generators_helper(messages.len());
    let indices_all_hidden = BTreeSet::<usize>::new();
    let signature =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            header,
            &generators,
            messages.clone(),
        )
        .expect("signing failed");

    // Proof is generated by passing invalid PublicKey which is identity element
    let (proof, revealed_messages) = test_helper::proof_gen(
        &PublicKey::default(),
        &signature,
        header,
        ph,
        &generators,
        &messages,
        &indices_all_hidden,
        &mut OsRng,
        "proof generation failed",
    );

    // The default proof has empty `m_hat_list`, i.e. no hidden message
    let default_proof = Proof::default();

    let mut one_revealed_message = BTreeMap::new();
    one_revealed_message.insert(NUM_MESSAGES, Message::random(&mut OsRng));

    let mut default_proof_1_hidden_message = Proof::default();
    default_proof_1_hidden_message.m_hat_list =
        vec![FiatShamirProof(Scalar::random(&mut OsRng)); 1];

    let mut default_proof_4_hidden_message = Proof::default();
    default_proof_4_hidden_message.m_hat_list =
        vec![FiatShamirProof(Scalar::random(&mut OsRng)); NUM_MESSAGES - 1];
    let mut revealed_messages_out_of_bound_index = BTreeMap::new();
    revealed_messages_out_of_bound_index
        .insert(NUM_MESSAGES, Message::random(&mut OsRng));

    [
        (
            (
                default_proof.clone(),
                key_pair.public_key,
                None,
                ph,
                generators.clone(),
                BTreeMap::new(),
            ),
            Error::BadParams {
                cause: format!("nothing to verify",),
            },
            "no header, x message-generators, no hidden messages, no revealed \
             messages",
        ),
        (
            (
                default_proof.clone(),
                key_pair.public_key,
                header,
                ph,
                create_generators_helper(1),
                BTreeMap::new(),
            ),
            Error::BadParams {
                cause: format!(
                    "Incorrect number of messages and generators: \
                     [#generators: 1, #hidden_messages: 0, \
                     #revealed_messages: 0]",
                ),
            },
            "no header, 1 message-generator, no hidden messages, no revealed \
             messages",
        ),
        (
            (
                default_proof_1_hidden_message.clone(),
                key_pair.public_key,
                header,
                ph,
                create_generators_helper(0),
                BTreeMap::new(),
            ),
            Error::BadParams {
                cause: format!(
                    "Incorrect number of messages and generators: \
                     [#generators: 0, #hidden_messages: 1, \
                     #revealed_messages: 0]",
                ),
            },
            "no header, no message-generators, 1 hidden message, no \
             revealed_messages",
        ),
        (
            (
                default_proof.clone(),
                key_pair.public_key,
                header,
                ph,
                create_generators_helper(0),
                one_revealed_message.clone(),
            ),
            Error::BadParams {
                cause: format!(
                    "Incorrect number of messages and generators: \
                     [#generators: 0, #hidden_messages: 0, \
                     #revealed_messages: 1]",
                ),
            },
            "no header, no message-generators, no hidden messages, 1 revealed \
             message, ",
        ),
        (
            (
                default_proof.clone(),
                key_pair.public_key,
                header,
                ph,
                create_generators_helper(1),
                BTreeMap::new(),
            ),
            Error::BadParams {
                cause: format!(
                    "Incorrect number of messages and generators: \
                     [#generators: 1, #hidden_messages: 0, \
                     #revealed_messages: 0]",
                ),
            },
            "valid header, 1 message-generator, no hidden messages, no \
             revealed messages",
        ),
        (
            (
                default_proof_1_hidden_message.clone(),
                key_pair.public_key,
                header,
                ph,
                create_generators_helper(0),
                BTreeMap::new(),
            ),
            Error::BadParams {
                cause: format!(
                    "Incorrect number of messages and generators: \
                     [#generators: 0, #hidden_messages: 1, \
                     #revealed_messages: 0]",
                ),
            },
            "valid header, no message-generators, 1 hidden message, no \
             revealed_messages",
        ),
        (
            (
                default_proof.clone(),
                key_pair.public_key,
                header,
                ph,
                create_generators_helper(0),
                one_revealed_message.clone(),
            ),
            Error::BadParams {
                cause: format!(
                    "Incorrect number of messages and generators: \
                     [#generators: 0, #hidden_messages: 0, \
                     #revealed_messages: 1]",
                ),
            },
            "valid header, no message-generators, no hidden messages, 1 \
             revealed message, ",
        ),
        (
            (
                default_proof_4_hidden_message,
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages_out_of_bound_index,
            ),
            Error::BadParams {
                cause: format!(
                    "revealed message index value is invalid, maximum allowed \
                     value is {}",
                    NUM_MESSAGES - 1
                ),
            },
            "revealed message index is equal to total no. of messages",
        ),
        (
            (
                proof.clone(),
                PublicKey::default(),
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            Error::InvalidPublicKey,
            "invalid public-key, public-key is identity element",
        ),
    ]
}

pub(crate) fn test_data_verify_tampered_proof() -> [(
    (
        Proof,
        PublicKey,
        Option<&'static [u8]>,
        Option<&'static [u8]>,
        MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter>,
        BTreeMap<usize, Message>,
    ),
    &'static str,
); 11] {
    const NUM_MESSAGES: usize = 5;
    let key_pair = get_random_test_key_pair();
    let header = Some(TEST_HEADER.as_ref());
    let ph = Some(TEST_PRESENTATION_HEADER_1.as_ref());
    let messages = get_random_test_messages(NUM_MESSAGES);
    let mut generators = create_generators_helper(messages.len());
    let indices_all_hidden = BTreeSet::<usize>::new();
    let signature =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            header,
            &generators,
            messages.clone(),
        )
        .expect("signing failed");

    // Generate a valid proof
    let (proof, revealed_messages) = test_helper::proof_gen(
        &key_pair.public_key,
        &signature,
        header,
        ph,
        &generators,
        &messages,
        &indices_all_hidden,
        &mut OsRng,
        "proof generation failed",
    );

    // Before tampering proof, make sure it is valid proof and verification
    // works
    assert_eq!(
        proof
            .verify::<_, _, Bls12381Shake256CipherSuiteParameter>(
                &key_pair.public_key,
                header,
                ph,
                &mut generators,
                &revealed_messages
            )
            .expect("proof verification failed"),
        true
    );

    [
        (
            (
                Proof {
                    A_bar: G1Projective::random(&mut OsRng),
                    m_hat_list: proof.m_hat_list.clone(),
                    ..proof
                },
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "A_bar is tampered",
        ),
        (
            (
                Proof {
                    B_bar: G1Projective::random(&mut OsRng),
                    m_hat_list: proof.m_hat_list.clone(),
                    ..proof
                },
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "B_bar is tampered",
        ),
        (
            (
                Proof {
                    D: G1Projective::random(&mut OsRng),
                    m_hat_list: proof.m_hat_list.clone(),
                    ..proof
                },
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "D is tampered",
        ),
        (
            (
                Proof {
                    c: Challenge(Scalar::random(&mut OsRng)),
                    m_hat_list: proof.m_hat_list.clone(),
                    ..proof
                },
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "c is tampered",
        ),
        (
            (
                Proof {
                    e_hat: FiatShamirProof(Scalar::random(&mut OsRng)),
                    m_hat_list: proof.m_hat_list.clone(),
                    ..proof
                },
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "e_hat is tampered",
        ),
        (
            (
                Proof {
                    s_hat: FiatShamirProof(Scalar::random(&mut OsRng)),
                    m_hat_list: proof.m_hat_list.clone(),
                    ..proof
                },
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "s_hat is tampered",
        ),
        (
            (
                Proof {
                    r2_hat: FiatShamirProof(Scalar::random(&mut OsRng)),
                    m_hat_list: proof.m_hat_list.clone(),
                    ..proof
                },
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "r2^ is tampered",
        ),
        (
            (
                Proof {
                    r3_hat: FiatShamirProof(Scalar::random(&mut OsRng)),
                    m_hat_list: proof.m_hat_list.clone(),
                    ..proof
                },
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "r3^ is tampered",
        ),
        (
            (
                Proof {
                    m_hat_list: vec![
                        FiatShamirProof(Scalar::random(&mut OsRng));
                        NUM_MESSAGES
                    ],
                    ..proof
                },
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "m_hat_list is tampered - all elements are different",
        ),
        (
            (
                Proof {
                    m_hat_list: vec![
                        FiatShamirProof(Scalar::random(&mut OsRng)),
                        proof.m_hat_list[1],
                        proof.m_hat_list[2],
                        proof.m_hat_list[3],
                        proof.m_hat_list[4],
                    ],
                    ..proof
                },
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "m_hat_list is tampered - first element is different",
        ),
        (
            (
                Proof {
                    m_hat_list: vec![
                        proof.m_hat_list[0],
                        proof.m_hat_list[1],
                        proof.m_hat_list[2],
                        proof.m_hat_list[3],
                        FiatShamirProof(Scalar::random(&mut OsRng)),
                    ],
                    ..proof
                },
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "m_hat_list is tampered - last element is different",
        ),
    ]
}

pub(crate) fn test_data_verify_tampered_parameters() -> [(
    (
        Proof,
        PublicKey,
        Option<&'static [u8]>,
        Option<&'static [u8]>,
        MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter>,
        BTreeMap<usize, Message>,
    ),
    &'static str,
); 14] {
    const NUM_MESSAGES: usize = 5;
    let key_pair = get_random_test_key_pair();
    let header = Some(TEST_HEADER.as_ref());
    let ph = Some(TEST_PRESENTATION_HEADER_1.as_ref());
    let messages = get_random_test_messages(NUM_MESSAGES);
    let mut generators = create_generators_helper(messages.len());
    let generators_different_q = test_generators_random_q(messages.len());
    let generators_different_message_generators =
        test_generators_random_message_generators(messages.len());

    let indices_all_hidden = BTreeSet::<usize>::new();

    let signature =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            header,
            &generators,
            messages.clone(),
        )
        .expect("signing failed");

    // Generate a valid proof
    let (proof_all_hidden_messages, no_revealed_messages) =
        test_helper::proof_gen(
            &key_pair.public_key,
            &signature,
            header,
            ph,
            &generators,
            &messages,
            &indices_all_hidden,
            &mut OsRng,
            "proof generation failed",
        );

    // Before tampering proof, make sure it is valid proof and verification
    // works
    assert_eq!(
        proof_all_hidden_messages
            .verify::<_, _, Bls12381Shake256CipherSuiteParameter>(
                &key_pair.public_key,
                header,
                ph,
                &mut generators,
                &no_revealed_messages
            )
            .expect("proof verification failed"),
        true
    );

    let no_header_signature =
        Signature::new::<&[u8], _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            None,
            &generators,
            messages.clone(),
        )
        .expect("signing failed");

    // Generate a valid proof
    let (no_header_proof, revealed_messages) = test_helper::proof_gen(
        &key_pair.public_key,
        &no_header_signature,
        None,
        ph,
        &generators,
        &messages,
        &indices_all_hidden,
        &mut OsRng,
        "proof generation failed",
    );

    // Before tampering proof, make sure it is valid proof and verification
    // works
    assert_eq!(
        no_header_proof
            .verify::<_, _, Bls12381Shake256CipherSuiteParameter>(
                &key_pair.public_key,
                None,
                ph,
                &mut generators,
                &revealed_messages
            )
            .expect("proof verification failed"),
        true
    );

    // Generate a valid proof
    let (no_ph_proof, revealed_messages) = test_helper::proof_gen(
        &key_pair.public_key,
        &signature,
        header,
        None,
        &generators,
        &messages,
        &indices_all_hidden,
        &mut OsRng,
        "proof generation failed",
    );

    // Before tampering proof, make sure it is valid proof and verification
    // works
    assert_eq!(
        no_ph_proof
            .verify::<_, _, Bls12381Shake256CipherSuiteParameter>(
                &key_pair.public_key,
                header,
                None,
                &mut generators,
                &revealed_messages
            )
            .expect("proof verification failed"),
        true
    );

    // Generate a valid proof
    let (no_header_no_ph_proof, revealed_messages) =
        test_helper::proof_gen::<&[u8], _, _>(
            &key_pair.public_key,
            &no_header_signature,
            None,
            None,
            &generators,
            &messages,
            &indices_all_hidden,
            &mut OsRng,
            "proof generation failed",
        );

    // Before tampering proof, make sure it is valid proof and verification
    // works
    assert_eq!(
        no_header_no_ph_proof
            .verify::<&[u8], _, Bls12381Shake256CipherSuiteParameter>(
                &key_pair.public_key,
                None,
                None,
                &mut generators,
                &revealed_messages
            )
            .expect("proof verification failed"),
        true
    );

    let indices_all_revealed = (0..NUM_MESSAGES)
        .collect::<Vec<usize>>()
        .iter()
        .cloned()
        .collect::<BTreeSet<usize>>();
    // Generate a valid proof
    let (proof_all_revealed_messages, all_revealed_messages) =
        test_helper::proof_gen(
            &key_pair.public_key,
            &signature,
            header,
            ph,
            &generators,
            &messages,
            &indices_all_revealed,
            &mut OsRng,
            "proof generation failed",
        );

    let all_revealed_but_different_messages = (0..NUM_MESSAGES)
        .map(|i| (i, Message::random(&mut OsRng)))
        .collect::<BTreeMap<usize, Message>>();

    let mut revealed_messages_first_elem_different =
        all_revealed_messages.clone();
    *revealed_messages_first_elem_different.get_mut(&0).unwrap() =
        Message::random(&mut OsRng);

    let mut revealed_messages_last_elem_different =
        all_revealed_messages.clone();
    *revealed_messages_last_elem_different
        .get_mut(&(NUM_MESSAGES - 1))
        .unwrap() = Message::random(&mut OsRng);

    // Before tampering proof, make sure it is valid proof and verification
    // works
    assert_eq!(
        proof_all_revealed_messages
            .verify::<_, _, Bls12381Shake256CipherSuiteParameter>(
                &key_pair.public_key,
                header,
                ph,
                &mut generators,
                &all_revealed_messages
            )
            .expect("proof verification failed"),
        true
    );

    [
        (
            (
                proof_all_hidden_messages.clone(),
                get_random_test_key_pair().public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "public key is different",
        ),
        (
            (
                proof_all_hidden_messages.clone(),
                key_pair.public_key,
                Some(ANOTHER_TEST_HEADER.as_ref()),
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "header is different",
        ),
        (
            (
                proof_all_hidden_messages.clone(),
                key_pair.public_key,
                None,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "header is different and None",
        ),
        (
            (
                proof_all_hidden_messages.clone(),
                key_pair.public_key,
                header,
                Some(TEST_PRESENTATION_HEADER_2.as_ref()),
                generators.clone(),
                revealed_messages.clone(),
            ),
            "presentation-header is different",
        ),
        (
            (
                proof_all_hidden_messages.clone(),
                key_pair.public_key,
                header,
                None,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "presentation-header is different and None",
        ),
        (
            (
                proof_all_hidden_messages.clone(),
                key_pair.public_key,
                header,
                ph,
                generators_different_q,
                revealed_messages.clone(),
            ),
            "Q value of generators is different",
        ),
        (
            (
                proof_all_hidden_messages.clone(),
                key_pair.public_key,
                header,
                ph,
                generators_different_message_generators,
                revealed_messages.clone(),
            ),
            "message-generators are different",
        ),
        (
            (
                no_header_proof.clone(),
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "proof has `None` header, header parameter is a `non-None` value",
        ),
        (
            (
                no_ph_proof.clone(),
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "proof has `None` ph, ph parameter is `non-None` value",
        ),
        (
            (
                no_header_no_ph_proof.clone(),
                key_pair.public_key,
                header,
                None,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "proof has `None` header, `None` ph, header parameter is a \
             `non-None` value, ph paramter is `None`",
        ),
        (
            (
                no_header_no_ph_proof.clone(),
                key_pair.public_key,
                None,
                ph,
                generators.clone(),
                revealed_messages.clone(),
            ),
            "proof has `None` header, `None` ph, header parameter is `None` \
             value, ph paramter is a `non-None`",
        ),
        (
            (
                proof_all_revealed_messages.clone(),
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                all_revealed_but_different_messages,
            ),
            "proof: all revealed messages, revealed_messages: all revealed \
             but all different messages",
        ),
        (
            (
                proof_all_revealed_messages.clone(),
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages_first_elem_different,
            ),
            "proof: all revealed messages, revealed_messages: all revealed \
             but first message is different",
        ),
        (
            (
                proof_all_revealed_messages.clone(),
                key_pair.public_key,
                header,
                ph,
                generators.clone(),
                revealed_messages_last_elem_different,
            ),
            "proof: all revealed messages, revealed_messages: all revealed \
             but last message is different",
        ),
    ]
}
pub(crate) fn test_data_from_octets_invalid_parameters(
) -> [(Vec<u8>, Error, &'static str); 26] {
    let a_bar = G1Projective::random(&mut OsRng).to_affine().to_compressed();
    let b_bar = G1Projective::random(&mut OsRng).to_affine().to_compressed();
    let d = G1Projective::random(&mut OsRng).to_affine().to_compressed();
    let c = Scalar::random(&mut OsRng).to_bytes_be();
    let e_hat = Scalar::random(&mut OsRng).to_bytes_be();
    let s_hat = Scalar::random(&mut OsRng).to_bytes_be();
    let r2_hat = Scalar::random(&mut OsRng).to_bytes_be();
    let r3_hat = Scalar::random(&mut OsRng).to_bytes_be();
    let m_hat_list = vec![Scalar::random(&mut OsRng).to_bytes_be(); 2];

    let g1_identity = G1Projective::identity().to_affine().to_compressed();
    //  let scalar_zero = Scalar::zero().to_bytes_be();
    let scalar_greater_than_modulus = [0xFF; OCTET_SCALAR_LENGTH];

    const PROOF_LEN_FLOOR: usize =
        OCTET_POINT_G1_LENGTH * 3 + OCTET_SCALAR_LENGTH * 5;

    [
        (
            vec![],
            Error::MalformedProof {
                cause: format!(
                    "not enough data, input buffer size: {} bytes",
                    0,
                ),
            },
            "empty input data",
        ),
        (
            vec![0xA; PROOF_LEN_FLOOR - 1],
            Error::MalformedProof {
                cause: format!(
                    "not enough data, input buffer size: {} bytes",
                    PROOF_LEN_FLOOR - 1,
                ),
            },
            "input data length is less than 1 from fixed base size",
        ),
        (
            vec![0xA; PROOF_LEN_FLOOR + 1],
            Error::MalformedProof {
                cause: format!(
                    "variable length proof data size {} is not multiple of \
                     `Scalar` size {} bytes",
                    1, OCTET_SCALAR_LENGTH
                ),
            },
            "input data length is greater than 1 from fixed base size",
        ),
        (
            vec![0xA; PROOF_LEN_FLOOR + OCTET_SCALAR_LENGTH - 1],
            Error::MalformedProof {
                cause: format!(
                    "variable length proof data size {} is not multiple of \
                     `Scalar` size {} bytes",
                    OCTET_SCALAR_LENGTH - 1,
                    OCTET_SCALAR_LENGTH
                ),
            },
            "variable input data length is less than 1 from the multiple of \
             `Scalar` size",
        ),
        (
            vec![0xA; PROOF_LEN_FLOOR + OCTET_SCALAR_LENGTH + 1],
            Error::MalformedProof {
                cause: format!(
                    "variable length proof data size {} is not multiple of \
                     `Scalar` size {} bytes",
                    OCTET_SCALAR_LENGTH + 1,
                    OCTET_SCALAR_LENGTH
                ),
            },
            "variable input data length is greater than 1 from the multiple \
             of `Scalar` size",
        ),
        (
            vec![0x0; PROOF_LEN_FLOOR],
            Error::BadEncoding,
            "input data is all zeroes",
        ),
        (
            [
                [0x0; OCTET_POINT_G1_LENGTH].as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::BadEncoding,
            "raw buffer for `Abar` is all zeroes",
        ),
        (
            [
                g1_identity.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::PointIsIdentity,
            "raw buffer for `Abar` is identity",
        ),
        (
            [
                a_bar.as_ref(),
                [0x0; OCTET_POINT_G1_LENGTH].as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::BadEncoding,
            "raw buffer for `Bbar` is all zeroes",
        ),
        (
            [
                a_bar.as_ref(),
                g1_identity.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::PointIsIdentity,
            "raw buffer for `Bbar` is identity",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `c` is all zeroes",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                scalar_greater_than_modulus.as_ref(),
            ]
            .concat(),
            Error::MalformedProof {
                cause: "failure while deserializing `c`".to_owned(),
            },
            "raw buffer value for `c` is larger than modulus",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                [0x0; OCTET_POINT_G1_LENGTH].as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::BadEncoding,
            "raw buffer for `D` is all zeroes",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                g1_identity.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::PointIsIdentity,
            "raw buffer for `D` is identity",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `e^` is all zeroes",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                scalar_greater_than_modulus.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::MalformedProof {
                cause: "failure while deserializing a `Scalar` value"
                    .to_owned(),
            },
            "raw buffer value for `e^` is larger than modulus",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `s^` is all zeroes",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                scalar_greater_than_modulus.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::MalformedProof {
                cause: "failure while deserializing a `Scalar` value"
                    .to_owned(),
            },
            "raw buffer value for `s^` is larger than modulus",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `r2^` is all zeroes",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                scalar_greater_than_modulus.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::MalformedProof {
                cause: "failure while deserializing a `Scalar` value"
                    .to_owned(),
            },
            "raw buffer value for `r2^` is larger than modulus",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `r3^` is all zeroes",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                scalar_greater_than_modulus.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::MalformedProof {
                cause: "failure while deserializing a `Scalar` value"
                    .to_owned(),
            },
            "raw buffer value for `r3^` is larger than modulus",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `m^_1` is all zeroes",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                scalar_greater_than_modulus.as_ref(),
                m_hat_list[1].as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::MalformedProof {
                cause: "failure while deserializing a `Scalar` value"
                    .to_owned(),
            },
            "raw buffer value for `m^_1` is larger than modulus",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                c.as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `m^_2` is all zeroes",
        ),
        (
            [
                a_bar.as_ref(),
                b_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                s_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                m_hat_list[0].as_ref(),
                scalar_greater_than_modulus.as_ref(),
                c.as_ref(),
            ]
            .concat(),
            Error::MalformedProof {
                cause: "failure while deserializing a `Scalar` value"
                    .to_owned(),
            },
            "raw buffer value for `m^_2` is larger than modulus",
        ),
    ]
}
