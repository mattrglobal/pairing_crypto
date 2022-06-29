use crate::{
    bbs::core::{
        constants::{
            GLOBAL_BLIND_VALUE_GENERATOR_SEED,
            OCTET_POINT_G1_LENGTH,
            OCTET_SCALAR_LENGTH,
        },
        generator::Generators,
        key_pair::{KeyPair, PublicKey},
        signature::Signature,
        types::Message,
    },
    curves::bls12_381::{G1Projective, Scalar},
    tests::bbs::{
        create_generators_helper,
        get_random_test_key_pair,
        get_random_test_messages,
        ANOTHER_TEST_HEADER,
        TEST_HEADER,
        TEST_PRESENTATION_HEADER_1,
        TEST_PRESENTATION_HEADER_2,
    },
    Error,
};
use ff::Field;
use group::{Curve, Group};
use hashbrown::HashSet;
use rand_core::OsRng;

pub(crate) fn test_data_proof_gen_verify_valid_cases() -> [(
    (
        KeyPair,
        Option<&'static [u8]>,
        Option<&'static [u8]>,
        Generators,
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
            "no header, no presentation-message, and equal no. of messages \
             and message-generators are provided",
        ),
        (
            (
                key_pair.clone(),
                header,
                None,
                generators.clone(),
                messages.clone(),
            ),
            "valid header, no presentation-message, no messages and no \
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
            "no header, valid presentation-message, and equal no. of messages \
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
            "valid header, valid presentation-message, no messages and no \
             message-generators are provided",
        ),
    ]
}

pub(crate) fn test_data_proof_gen_error_cases() -> [(
    (
        PublicKey,
        Signature,
        Option<&'static [u8]>,
        Option<&'static [u8]>,
        Generators,
        Vec<Message>,
        HashSet<usize>,
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
    let indices_all_hidden = HashSet::<usize>::new();
    let signature = Signature::new(
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
            "no header, no presentation-message, no messages, no \
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
            "no header, no presentation-message, no messages but \
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
            "no header, no presentation-message, no message-generators but \
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
                generators: generators.message_blinding_points_length(),
                messages: 2,
            },
            "no header, no presentation-message, more message-generators than \
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
            "no header, no presentation-message, more messages than \
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
            "no header, valid presentation-message, no messages but \
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
            "no header, valid presentation-message, no message-generators but \
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
                generators: generators.message_blinding_points_length(),
                messages: 2,
            },
            "no header, valid presentation-message, more message-generators \
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
            "no header, valid presentation-message, more messages than \
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
            "valid header, no presentation-message, no message-generators but \
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
                generators: generators.message_blinding_points_length(),
                messages: 0,
            },
            "valid header, no presentation-message, no messages but \
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
                generators: generators.message_blinding_points_length(),
                messages: 2,
            },
            "valid header, no presentation-message, more message-generators \
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
            "valid header, no presentation-message, more messages than \
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
            "valid header, valid presentation-message, no message-generators \
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
                generators: generators.message_blinding_points_length(),
                messages: 0,
            },
            "valid header, valid presentation-message, no messages but \
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
                generators: generators.message_blinding_points_length(),
                messages: 2,
            },
            "valid header, valid presentation-message, more \
             message-generators than messages",
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
            "valid header, valid presentation-message, more messages than \
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
        Generators,
        Vec<Message>,
        HashSet<usize>,
    ),
    (
        PublicKey,
        Signature,
        Option<&'static [u8]>,
        Option<&'static [u8]>,
        Generators,
        Vec<Message>,
        HashSet<usize>,
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
    let generators_different_message_gens_seed = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        b"test-message-generators-seed-2".as_ref(),
        messages.len(),
    )
    .expect(
        "generators creation with different message generators seed failed",
    );
    let indices: Vec<usize> = (0..NUM_MESSAGES).collect();
    let indices_all_hidden = HashSet::<usize>::new();
    let indices_all_revealed =
        indices.iter().cloned().collect::<HashSet<usize>>();
    let first_and_last_indices_revealed = [0, NUM_MESSAGES - 1]
        .iter()
        .cloned()
        .collect::<HashSet<usize>>();
    let signature = Signature::new(
        &key_pair.secret_key,
        &key_pair.public_key,
        header,
        &generators,
        messages.clone(),
    )
    .expect("signing failed");
    let signature_with_different_key_pair = Signature::new(
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
                generators_different_message_gens_seed.clone(),
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

pub(crate) fn test_data_from_octets_error_cases(
) -> [(Vec<u8>, Error, &'static str); 26] {
    let a_prime = G1Projective::random(&mut OsRng).to_affine().to_compressed();
    let a_bar = G1Projective::random(&mut OsRng).to_affine().to_compressed();
    let d = G1Projective::random(&mut OsRng).to_affine().to_compressed();
    let c = Scalar::random(&mut OsRng).to_bytes_be();
    let e_hat = Scalar::random(&mut OsRng).to_bytes_be();
    let r2_hat = Scalar::random(&mut OsRng).to_bytes_be();
    let r3_hat = Scalar::random(&mut OsRng).to_bytes_be();
    let s_hat = Scalar::random(&mut OsRng).to_bytes_be();
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
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::BadEncoding,
            "raw buffer for `A'` is all zeroes",
        ),
        (
            [
                g1_identity.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::PointIsIdentity,
            "raw buffer for `A'` is identity",
        ),
        (
            [
                a_prime.as_ref(),
                [0x0; OCTET_POINT_G1_LENGTH].as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::BadEncoding,
            "raw buffer for `A_bar` is all zeroes",
        ),
        (
            [
                a_prime.as_ref(),
                g1_identity.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::PointIsIdentity,
            "raw buffer for `A_bar` is identity",
        ),
        (
            [
                a_prime.as_ref(),
                a_bar.as_ref(),
                [0x0; OCTET_POINT_G1_LENGTH].as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::BadEncoding,
            "raw buffer for `D` is all zeroes",
        ),
        (
            [
                a_prime.as_ref(),
                a_bar.as_ref(),
                g1_identity.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::PointIsIdentity,
            "raw buffer for `D` is identity",
        ),
        (
            [
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `c` is all zeroes",
        ),
        (
            [
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                scalar_greater_than_modulus.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::MalformedProof {
                cause: "failure while deserializing `c`".to_owned(),
            },
            "raw buffer value for `c` is larger than modulus",
        ),
        (
            [
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `e^` is all zeroes",
        ),
        (
            [
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                scalar_greater_than_modulus.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
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
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `r2^` is all zeroes",
        ),
        (
            [
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                scalar_greater_than_modulus.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
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
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `r3^` is all zeroes",
        ),
        (
            [
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                scalar_greater_than_modulus.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
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
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `s^` is all zeroes",
        ),
        (
            [
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                scalar_greater_than_modulus.as_ref(),
                m_hat_list[0].as_ref(),
                m_hat_list[1].as_ref(),
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
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                m_hat_list[1].as_ref(),
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `m^_1` is all zeroes",
        ),
        (
            [
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                scalar_greater_than_modulus.as_ref(),
                m_hat_list[1].as_ref(),
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
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
            ]
            .concat(),
            Error::UnexpectedZeroValue,
            "raw buffer for `m^_2` is all zeroes",
        ),
        (
            [
                a_prime.as_ref(),
                a_bar.as_ref(),
                d.as_ref(),
                c.as_ref(),
                e_hat.as_ref(),
                r2_hat.as_ref(),
                r3_hat.as_ref(),
                s_hat.as_ref(),
                m_hat_list[0].as_ref(),
                scalar_greater_than_modulus.as_ref(),
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
