use super::{
    create_generators_helper,
    EXPECTED_SIGNATURES,
    TEST_CLAIMS,
    TEST_HEADER,
    TEST_KEY_GEN_IKM,
    TEST_KEY_INFO,
    TEST_KEY_INFOS,
};
use crate::{
    bbs::{
        ciphersuites::bls12_381::{
            Message,
            PublicKey,
            SecretKey,
            Signature,
            MAP_MESSAGE_TO_SCALAR_DST,
        },
        core::{
            constants::{
                GLOBAL_BLIND_VALUE_GENERATOR_SEED,
                GLOBAL_MESSAGE_GENERATOR_SEED,
                GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
                OCTET_POINT_G1_LENGTH,
                OCTET_SCALAR_LENGTH,
            },
            generator::Generators,
            key_pair::KeyPair,
        },
    },
    curves::bls12_381::{G1Projective, Scalar},
    from_vec_deserialization_invalid_vec_size,
    tests::bbs::EXPECTED_SIGNATURE,
    Error,
};
use core::convert::TryFrom;
use ff::Field;
use group::{Curve, Group};
use rand_core::OsRng;
use subtle::{Choice, ConditionallySelectable};

fn create_messages_helper() -> Vec<Message> {
    TEST_CLAIMS
        .iter()
        .map(|b| {
            Message::from_arbitrary_data(
                b.as_ref(),
                MAP_MESSAGE_TO_SCALAR_DST.as_ref(),
            )
        })
        .collect::<Result<Vec<Message>, _>>()
        .expect("claims to `Message` conversion failed")
}

#[test]
fn sign_verify_serde_nominal() {
    let key_pair = KeyPair::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("key pair generation failed");
    let header = Some(&TEST_HEADER);
    let messages = create_messages_helper();
    let generators = create_generators_helper(messages.len());

    let signature = Signature::new(
        &key_pair.secret_key,
        &key_pair.public_key,
        header,
        &generators,
        &messages,
    )
    .expect("signing failed");

    assert_eq!(
        signature
            .verify(&key_pair.public_key, header, &generators, &messages)
            .expect("verification failed"),
        true
    );

    let signature_octets = signature.to_octets();
    let signature_from_deserialization =
        Signature::from_octets(signature_octets)
            .expect("signature deserialization failed");
    assert_eq!(
        signature, signature_from_deserialization,
        "signature serde failed"
    );

    assert_eq!(
        signature_from_deserialization
            .verify(&key_pair.public_key, header, &generators, &messages)
            .expect("signature verification failed after serde"),
        true
    );
}

#[test]
fn sign_verify_different_key_infos() {
    let messages = create_messages_helper();

    for i in 0..TEST_KEY_INFOS.len() {
        let sk = SecretKey::new(
            TEST_KEY_GEN_IKM.as_ref(),
            TEST_KEY_INFOS[i].as_ref(),
        )
        .expect("secret key generation failed");
        let pk = PublicKey::from(&sk);
        let generators = create_generators_helper(messages.len());
        let signature = Signature::new(
            &sk,
            &pk,
            Some(&TEST_HEADER),
            &generators,
            &messages,
        )
        .expect("signing failed");
        // println!("{:?},", hex::encode(signature.to_octets()));

        assert_eq!(
            signature
                .verify(&pk, Some(&TEST_HEADER), &generators, &messages)
                .unwrap(),
            true
        );
        let expected_signature = Signature::from_octets(
            &<[u8; Signature::SIZE_BYTES]>::try_from(
                hex::decode(EXPECTED_SIGNATURES[i])
                    .expect("hex decoding failed"),
            )
            .expect("data conversion failed"),
        )
        .expect("signature deserialization failed");
        assert_eq!(signature, expected_signature);
    }
}

#[test]
fn signature_equality() {
    let key_pair = KeyPair::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("key pair generation failed");
    let header = Some(&TEST_HEADER);
    let messages = create_messages_helper();
    let generators = create_generators_helper(messages.len());

    let signature1 = Signature::new(
        &key_pair.secret_key,
        &key_pair.public_key,
        header,
        &generators,
        &messages,
    )
    .expect("signing failed");

    let signature2 = Signature::new(
        &key_pair.secret_key,
        &key_pair.public_key,
        header,
        &generators,
        &messages,
    )
    .expect("signing failed");

    assert_eq!(signature1, signature2);
    assert_eq!(signature1, signature1);
    assert_eq!(signature2, signature2);

    let mut signature3 = Signature::default();
    signature3.conditional_assign(&signature1, Choice::from(1u8));
    assert_eq!(signature3, signature1);

    let mut signature4 = Signature::default();
    signature4.conditional_assign(&signature1, Choice::from(0u8));
    assert_ne!(signature4, signature1);

    let signature5 = Signature::new(
        &key_pair.secret_key,
        &key_pair.public_key,
        header,
        &create_generators_helper(0),
        &vec![],
    )
    .expect("signing failed");

    assert_ne!(signature5, signature1);
}

#[test]
fn sign_verify_valid_cases() {
    let sk = SecretKey::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("secret key generation failed");
    let pk = PublicKey::from(&sk);
    let header = Some(&TEST_HEADER);
    let messages = create_messages_helper();
    let generators = create_generators_helper(messages.len());

    // [(SK, PK, header, generators, messages, failure-debug-message)]
    let test_data = [
        (
            &sk,
            &pk,
            header,
            &create_generators_helper(0),
            &vec![],
            "valid header, no messages and no generators are provided",
        ),
        (
            &sk,
            &pk,
            None,
            &generators,
            &messages,
            "no header, but equal no. of messages and generators are provided",
        ),
    ];

    for (sk, pk, header, generators, messages, failure_debug_message) in
        test_data
    {
        let signature = Signature::new(sk, &pk, header, &generators, &messages)
            .expect(&format!("signing should pass - {failure_debug_message}"));
        assert_eq!(
            signature
                .verify(&pk, header, &generators, &messages)
                .expect(&format!(
                    "verification should pass - {failure_debug_message}"
                )),
            true
        );
    }

    // Public key validity is not checked during signing
    Signature::new(&sk, &PublicKey::default(), header, &generators, &messages)
        .expect(&format!(
            "signing should pass - public key validity is not checked during \
             signing"
        ));
}

#[test]
// Test `Signature::new(...)` implementations error returns by passing invalid
// passing paramter values.
fn signature_new_error_cases() {
    let sk = SecretKey::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("secret key generation failed");
    let pk = PublicKey::from(&sk);
    let header = Some(&TEST_HEADER);
    let messages = create_messages_helper();
    let generators = create_generators_helper(messages.len());
    // Just to make sure sign-verify succeeds with above valid values
    let signature = Signature::new(&sk, &pk, header, &generators, &messages)
        .expect("signing failed");
    assert_eq!(
        signature
            .verify(&pk, header, &generators, &messages)
            .expect("verification failed"),
        true
    );

    // [(SK, PK, header, generators, messages, result, failure-debug-message)]
    let test_data = [
        (
            &sk,
            &pk,
            None,
            &generators,
            &vec![],
            Error::BadParams {
                cause: "nothing to sign".to_owned(),
            },
            "no header and no messages",
        ),
        (
            &SecretKey::default(),
            &pk,
            header,
            &create_generators_helper(0),
            &messages,
            Error::MessageGeneratorsLengthMismatch {
                generators: 0,
                messages: messages.len(),
            },
            "valid header, no generators but messages are provided",
        ),
        (
            &SecretKey::default(),
            &pk,
            header,
            &generators,
            &vec![],
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_blinding_points_length(),
                messages: 0,
            },
            "valid header, no messages but generators are provided",
        ),
        (
            &SecretKey::default(),
            &pk,
            header,
            &generators,
            &vec![Message::default(); 2],
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_blinding_points_length(),
                messages: 2,
            },
            "more generators than messages",
        ),
        (
            &SecretKey::default(),
            &pk,
            header,
            &create_generators_helper(2),
            &messages,
            Error::MessageGeneratorsLengthMismatch {
                generators: 2,
                messages: messages.len(),
            },
            "more messages than generators",
        ),
        (
            &SecretKey::default(),
            &pk,
            header,
            &generators,
            &messages,
            Error::InvalidSecretKey,
            "secret key is zero",
        ),
    ];

    for (sk, pk, header, generators, messages, error, failure_debug_message) in
        test_data
    {
        let result = Signature::new(sk, &pk, header, &generators, &messages);
        assert_eq!(
            result,
            Err(error),
            "signing should fail - {}",
            failure_debug_message
        );
    }
}

#[test]
// Test if `verify` succeeds with tampered signature components.
fn verify_tampered_signature() {
    let key_pair = KeyPair::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("key pair generation failed");
    let header = Some(TEST_HEADER.as_ref());
    let messages = create_messages_helper();
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )
    .expect("generators creation failed");

    // Just to make sure sign-verify succeeds with above valid values
    let signature = Signature::new(
        &key_pair.secret_key,
        &key_pair.public_key,
        header,
        &generators,
        &messages,
    )
    .expect("signing failed");
    assert_eq!(
        signature
            .verify(&key_pair.public_key, header, &generators, &messages)
            .expect("verification failed"),
        true
    );

    let mut tampered_signature = signature;
    tampered_signature.A = G1Projective::random(&mut OsRng);
    assert_eq!(
        tampered_signature
            .verify(&key_pair.public_key, header, &generators, &messages)
            .expect("verification should not fail with error"),
        false,
        "verification should fail with tampered `A` value"
    );

    tampered_signature = signature;
    tampered_signature.e = Scalar::random(&mut OsRng);
    assert_eq!(
        tampered_signature
            .verify(&key_pair.public_key, header, &generators, &messages)
            .expect("verification should not fail with error"),
        false,
        "verification should fail with tampered `e` value"
    );

    tampered_signature = signature;
    tampered_signature.s = Scalar::random(&mut OsRng);
    assert_eq!(
        tampered_signature
            .verify(&key_pair.public_key, header, &generators, &messages)
            .expect("verification should not fail with error"),
        false,
        "verification should fail with tampered `s` value"
    );
}

// Rotate the passed vector if (rotate_by < v.len()), otherwise return passed
// unmodified passed vector.
fn vec_rotation_helper<T: Clone>(
    v: &Vec<T>,
    rotate_by: usize,
    rotate_left: bool,
) -> Vec<T> {
    let mut rotated_v = v.clone();
    if rotate_by < v.len() {
        if rotate_left {
            rotated_v.rotate_left(rotate_by)
        } else {
            rotated_v.rotate_right(rotate_by)
        }
    }
    rotated_v.to_vec()
}

// Test `verify` with different paramter values different than those used to
// produce the signature. All these test cases should return an `Ok(false)`, not
// errors.
fn verify_tampered_signature_parameters_helper(messages: Vec<Message>) {
    let key_pair = KeyPair::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("key pair generation failed");
    let header = Some(TEST_HEADER.as_ref());
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )
    .expect("generators creation failed");

    // Just to make sure sign-verify succeeds with above valid values
    let signature = Signature::new(
        &key_pair.secret_key,
        &key_pair.public_key,
        header,
        &generators,
        &messages,
    )
    .expect("signing failed");
    assert_eq!(
        signature
            .verify(&key_pair.public_key, header, &generators, &messages)
            .expect("verification failed"),
        true
    );

    // Another set of variables to be used as tampered values
    let different_key_pair =
        KeyPair::random(&mut OsRng, TEST_KEY_INFO.as_ref())
            .expect("key pair generation failed");
    let different_header = Some(b"another-set-of-header".as_ref());
    let generators_different_blind_value_seed = Generators::new(
        b"test-blind-value-seed-2".as_ref(),
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )
    .expect("generators creation with different blind value seed failed");
    let generators_different_sig_domain_seed = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        b"test-sig-domain-seed-2".as_ref(),
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )
    .expect("generators creation with different sig domain seed failed");
    let generators_different_message_gens_seed = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        b"test-message-generators-seed-2".as_ref(),
        messages.len(),
    )
    .expect(
        "generators creation with different message generators seed failed",
    );

    let mut messages_one_extra_message_at_start = messages.clone();
    messages_one_extra_message_at_start.insert(0, Message::random(&mut OsRng));
    let mut messages_one_extra_message_at_last = messages.clone();
    messages_one_extra_message_at_last.push(Message::random(&mut OsRng));
    let mut messages_fist_message_removed = messages.clone();
    messages_fist_message_removed.remove(0);
    let mut messages_last_message_removed = messages.clone();
    messages_last_message_removed.remove(messages.len() - 1);
    let mut messages_different_first_message = messages.clone();
    *messages_different_first_message.first_mut().unwrap() =
        Message::random(&mut OsRng);
    let mut messages_different_last_message = messages.clone();
    *messages_different_last_message.last_mut().unwrap() =
        Message::random(&mut OsRng);

    // [(PK, header, generators, messages, failure-debug-message)]
    let test_data = [
        (
            &different_key_pair.public_key,
            header,
            &generators,
            &messages,
            "different public key",
        ),
        (
            &key_pair.public_key,
            None,
            &generators,
            &messages,
            "no header",
        ),
        (
            &key_pair.public_key,
            different_header,
            &generators,
            &messages,
            "different header",
        ),
        (
            &key_pair.public_key,
            header,
            &generators_different_blind_value_seed,
            &messages,
            "different blind value seed generator",
        ),
        (
            &key_pair.public_key,
            header,
            &generators_different_sig_domain_seed,
            &messages,
            "different sign domain seed generator",
        ),
        (
            &key_pair.public_key,
            header,
            &generators_different_message_gens_seed,
            &messages,
            "different message generators seed generators",
        ),
        (
            &key_pair.public_key,
            header,
            &create_generators_helper(
                messages_one_extra_message_at_start.len(),
            ),
            &messages_one_extra_message_at_start,
            "one extra message at start",
        ),
        (
            &key_pair.public_key,
            header,
            &create_generators_helper(
                messages_one_extra_message_at_start.len(),
            ),
            &messages_one_extra_message_at_last,
            "one extra message at last",
        ),
        (
            &key_pair.public_key,
            header,
            &create_generators_helper(messages_fist_message_removed.len()),
            &messages_fist_message_removed,
            "first message removed",
        ),
        (
            &key_pair.public_key,
            header,
            &create_generators_helper(messages_last_message_removed.len()),
            &messages_last_message_removed,
            "last message removed",
        ),
        (
            &key_pair.public_key,
            header,
            &generators,
            &messages_different_first_message,
            "different first message",
        ),
        (
            &key_pair.public_key,
            header,
            &generators,
            &messages_different_last_message,
            "different last message",
        ),
        (
            &key_pair.public_key,
            header,
            &generators,
            &vec![
                Message::random(&mut OsRng);
                generators.message_blinding_points_length()
            ],
            "all messages are different",
        ),
    ];

    for (pk, header, generators, messages, failure_debug_message) in test_data {
        let result = signature
            .verify(&pk, header, &generators, &messages)
            .expect("verify should return a true/false value, not error");
        assert_eq!(
            result, false,
            "verification should fail - {}",
            failure_debug_message
        );
    }

    // Multi-message cases
    if messages.len() >= 2 {
        let mut messages_reversed = messages.clone();
        messages_reversed.reverse();

        // [(PK, header, generators, messages, failure-debug-message)]
        let test_data = [
            (
                &key_pair.public_key,
                header,
                &generators,
                &messages_reversed,
                "messages reversed",
            ),
            (
                &key_pair.public_key,
                header,
                &generators,
                &vec_rotation_helper(&messages, 1, true),
                "messages left-rotated-by-1",
            ),
            (
                &key_pair.public_key,
                header,
                &generators,
                &vec_rotation_helper(&messages, 1, false),
                "messages right-rotated-by-1",
            ),
        ];

        for (pk, header, generators, messages, failure_debug_message) in
            test_data
        {
            let result = signature
                .verify(&pk, header, &generators, &messages)
                .expect("verify should return a true/false value, not error");
            assert_eq!(
                result, false,
                "verification should fail - {}",
                failure_debug_message
            );
        }
    }
}

#[test]
// Test `verify` with different paramter values different than those used to
// produce the signature. All these test cases should return an `Ok(false)`, not
// errors. In this variant, a single message is used to produce signature.
fn verify_tampered_signature_parameters_single_message_signature() {
    verify_tampered_signature_parameters_helper(vec![Message::random(
        &mut OsRng,
    )]);
}

#[test]
// Test `verify` with different paramter values different than those used to
// produce the signature. All these test cases should return an `Ok(false)`, not
// errors. In this variant, multiple messages are used to produce signature.
fn verify_tampered_signature_parameters_multi_message_signature() {
    verify_tampered_signature_parameters_helper(create_messages_helper());
}

#[test]
// Test as above test case `verify_tampered_signature_parameters` but here
// original signature is produced with `header` being `None`.
fn verify_tampered_signature_parameters_no_header_signature() {
    let key_pair = KeyPair::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("key pair generation failed");
    let header = None;
    let messages = create_messages_helper();
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )
    .expect("generators creation failed");

    // Just to make sure sign-verify succeeds with above valid values
    let signature = Signature::new(
        &key_pair.secret_key,
        &key_pair.public_key,
        header,
        &generators,
        &messages,
    )
    .expect("signing failed");
    assert_eq!(
        signature
            .verify(&key_pair.public_key, header, &generators, &messages)
            .expect("verification failed"),
        true
    );

    // Another set of variables to be used as tampered values
    let different_key_pair =
        KeyPair::random(&mut OsRng, TEST_KEY_INFO.as_ref())
            .expect("key pair generation failed");
    let different_header = Some(b"another-set-of-header".as_ref());
    let generators_different_blind_value_seed = Generators::new(
        b"test-blind-value-seed-2".as_ref(),
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )
    .expect("generators creation with different blind value seed failed");
    let generators_different_sig_domain_seed = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        b"test-sig-domain-seed-2".as_ref(),
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )
    .expect("generators creation with different sig domain seed failed");
    let generators_different_message_gens_seed = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        b"test-message-generators-seed-2".as_ref(),
        messages.len(),
    )
    .expect(
        "generators creation with different message generators seed failed",
    );
    let mut messages_different_first_message = messages.clone();
    *messages_different_first_message.first_mut().unwrap() =
        Message::random(&mut OsRng);
    let mut messages_different_last_message = messages.clone();
    *messages_different_last_message.last_mut().unwrap() =
        Message::random(&mut OsRng);

    // [(PK, header, generators, messages, failure-debug-message)]
    let test_data = [
        (
            &different_key_pair.public_key,
            header,
            &generators,
            &messages,
            "different public key",
        ),
        (
            &key_pair.public_key,
            different_header,
            &generators,
            &messages,
            "different header",
        ),
        (
            &key_pair.public_key,
            header,
            &generators_different_blind_value_seed,
            &messages,
            "different blind value seed generator",
        ),
        (
            &key_pair.public_key,
            header,
            &generators_different_sig_domain_seed,
            &messages,
            "different sign domain seed generator",
        ),
        (
            &key_pair.public_key,
            header,
            &generators_different_message_gens_seed,
            &messages,
            "different message generators seed generators",
        ),
        (
            &key_pair.public_key,
            header,
            &generators,
            &messages_different_first_message,
            "different first message",
        ),
        (
            &key_pair.public_key,
            header,
            &generators,
            &messages_different_last_message,
            "different last message",
        ),
        (
            &key_pair.public_key,
            header,
            &generators,
            &vec![
                Message::random(&mut OsRng);
                generators.message_blinding_points_length()
            ],
            "all messages are different",
        ),
    ];

    for (pk, header, generators, messages, failure_debug_message) in test_data {
        let result = signature
            .verify(&pk, header, &generators, &messages)
            .expect("verify should return a true/false value, not error");
        assert_eq!(
            result, false,
            "verification should fail - {}",
            failure_debug_message
        );
    }
}

#[test]
// Test as above test case `verify_tampered_signature_parameters` but here
// original signature is produced with no messages.
fn verify_tampered_signature_parameters_no_messages_signature() {
    let key_pair = KeyPair::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("key pair generation failed");
    let header = Some(TEST_HEADER.as_ref());
    let messages = vec![];
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )
    .expect("generators creation failed");

    // Just to make sure sign-verify succeeds with above valid values
    let signature = Signature::new(
        &key_pair.secret_key,
        &key_pair.public_key,
        header,
        &generators,
        &messages,
    )
    .expect("signing failed");
    assert_eq!(
        signature
            .verify(&key_pair.public_key, header, &generators, &messages)
            .expect("verification failed"),
        true
    );

    // Another set of variables to be used as tampered values
    let different_key_pair =
        KeyPair::random(&mut OsRng, TEST_KEY_INFO.as_ref())
            .expect("key pair generation failed");
    let different_header = Some(b"another-set-of-header".as_ref());
    let generators_different_blind_value_seed = Generators::new(
        b"test-blind-value-seed-2".as_ref(),
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )
    .expect("generators creation with different blind value seed failed");
    let generators_different_sig_domain_seed = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        b"test-sig-domain-seed-2".as_ref(),
        GLOBAL_MESSAGE_GENERATOR_SEED,
        messages.len(),
    )
    .expect("generators creation with different sig domain seed failed");

    // [(PK, header, generators, messages, failure-debug-message)]
    let test_data = [
        (
            &different_key_pair.public_key,
            header,
            &generators,
            &messages,
            "different public key",
        ),
        (
            &key_pair.public_key,
            different_header,
            &generators,
            &messages,
            "different header",
        ),
        (
            &key_pair.public_key,
            header,
            &generators_different_blind_value_seed,
            &messages,
            "different blind value seed generator",
        ),
        (
            &key_pair.public_key,
            header,
            &generators_different_sig_domain_seed,
            &messages,
            "different sign domain seed generator",
        ),
    ];

    for (pk, header, generators, messages, failure_debug_message) in test_data {
        let result = signature
            .verify(&pk, header, &generators, &messages)
            .expect("verify should return a true/false value, not error");
        assert_eq!(
            result, false,
            "verification should fail - {}",
            failure_debug_message
        );
    }
}

#[test]
fn verify_error_cases() {
    let sk = SecretKey::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("secret key generation failed");
    let pk = PublicKey::from(&sk);
    let header = Some(&TEST_HEADER);
    let messages = create_messages_helper();
    let generators = create_generators_helper(messages.len());
    // Just to make sure sign-verify succeeds with above valid values
    let signature = Signature::new(&sk, &pk, header, &generators, &messages)
        .expect("signing failed");
    assert_eq!(
        signature
            .verify(&pk, header, &generators, &messages)
            .expect("verification failed"),
        true
    );

    // [(PK, header, generators, messages, result, failure-debug-message)]
    let test_data = [
        (
            &pk,
            None,
            &generators,
            &vec![],
            Error::BadParams {
                cause: "nothing to verify".to_owned(),
            },
            "no header and no messages",
        ),
        (
            &pk,
            header,
            &create_generators_helper(0),
            &messages,
            Error::MessageGeneratorsLengthMismatch {
                generators: 0,
                messages: messages.len(),
            },
            "valid header, no generators but messages are provided",
        ),
        (
            &pk,
            header,
            &generators,
            &vec![],
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_blinding_points_length(),
                messages: 0,
            },
            "valid header, no messages but generators are provided",
        ),
        (
            &pk,
            header,
            &generators,
            &vec![Message::default(); 2],
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_blinding_points_length(),
                messages: 2,
            },
            "more generators than messages",
        ),
        (
            &pk,
            header,
            &create_generators_helper(2),
            &messages,
            Error::MessageGeneratorsLengthMismatch {
                generators: 2,
                messages: messages.len(),
            },
            "more messages than generators",
        ),
        (
            &PublicKey::default(),
            header,
            &generators,
            &messages,
            Error::InvalidPublicKey,
            "public key is identity",
        ),
    ];

    for (pk, header, generators, messages, error, failure_debug_message) in
        test_data
    {
        let result = signature.verify(&pk, header, &generators, &messages);
        assert_eq!(
            result,
            Err(error),
            "verification should fail - {}",
            failure_debug_message
        );
    }
}

// Concat `A`, `e` and `s` component of `Signature` as `Vec`.
macro_rules! concat_a_e_s {
    ($a:expr, $e:expr, $s:expr) => {
        [
            [
                $a.to_affine().to_compressed().as_ref(),
                $e.to_bytes_be().as_ref(),
            ]
            .concat(),
            $s.to_bytes_be().as_ref().to_vec(),
        ]
        .concat()
    };
}

#[test]
fn to_octets() {
    let key_pair =
        KeyPair::new(TEST_KEY_GEN_IKM.as_ref(), TEST_KEY_INFO.as_ref())
            .expect("key pair generation failed");
    let header = Some(&TEST_HEADER);
    let messages = create_messages_helper();
    let generators = create_generators_helper(messages.len());

    let mut signature = Signature::new(
        &key_pair.secret_key,
        &key_pair.public_key,
        header,
        &generators,
        &messages,
    )
    .expect("signing failed");

    let mut signature_octets = signature.to_octets();
    let expected_signature_octets = <[u8; Signature::SIZE_BYTES]>::try_from(
        hex::decode(EXPECTED_SIGNATURE).expect("hex decoding failed"),
    )
    .expect("signature hex decoding failed");
    assert_eq!(signature_octets, expected_signature_octets);

    let a = G1Projective::random(&mut OsRng);
    let e = Scalar::random(&mut OsRng);
    let s = Scalar::random(&mut OsRng);

    signature = Signature { A: a, e, s };
    signature_octets = signature.to_octets();
    let expected_signature_octets = concat_a_e_s!(a, e, s);
    assert_eq!(signature_octets, expected_signature_octets.as_ref());
}

#[test]
fn from_vec_deserialization() {
    let mut signature = Signature::default();
    signature.A = G1Projective::random(&mut OsRng);
    signature.e = Scalar::random(&mut OsRng);
    signature.s = Scalar::random(&mut OsRng);
    let signature_octets = signature.to_octets();

    let signature_from_vec = Signature::from_vec(&Vec::from(signature_octets))
        .expect("`Signature::from_vec(...)` should not fail");
    assert_eq!(signature, signature_from_vec);

    from_vec_deserialization_invalid_vec_size!(Signature);
}

// Concat 3 input buffers.
macro_rules! concat_3 {
    ($a:expr, $e:expr, $s:expr) => {
        [[$a.as_ref(), $e.as_ref()].concat(), $s.to_vec()].concat()
    };
}

#[test]
fn from_octets() {
    let test_data = [
        (
            vec![],
            Error::MalformedSignature {
                cause: format!(
                    "invalid input buffer size: {} bytes, expected data size: \
                     {} bytes",
                    0,
                    Signature::SIZE_BYTES
                ),
            },
            "empty input data",
        ),
        (
            vec![0xA; Signature::SIZE_BYTES - 1],
            Error::MalformedSignature {
                cause: format!(
                    "invalid input buffer size: {} bytes, expected data size: \
                     {} bytes",
                    Signature::SIZE_BYTES - 1,
                    Signature::SIZE_BYTES
                ),
            },
            "input data length is less than 1 from expected",
        ),
        (
            vec![0xB; Signature::SIZE_BYTES + 1],
            Error::MalformedSignature {
                cause: format!(
                    "invalid input buffer size: {} bytes, expected data size: \
                     {} bytes",
                    Signature::SIZE_BYTES + 1,
                    Signature::SIZE_BYTES
                ),
            },
            "input data length is greater than 1 from expected",
        ),
        (
            vec![0x0; Signature::SIZE_BYTES],
            Error::BadEncoding,
            "input data is all zeroes",
        ),
        (
            concat_3!(
                &vec![0x0; OCTET_POINT_G1_LENGTH],
                Scalar::random(&mut OsRng).to_bytes_be(),
                Scalar::random(&mut OsRng).to_bytes_be()
            ),
            Error::BadEncoding,
            "Raw buffer for `A` is all zeroes",
        ),
        (
            concat_3!(
                &vec![0xA; OCTET_POINT_G1_LENGTH],
                Scalar::random(&mut OsRng).to_bytes_be(),
                Scalar::random(&mut OsRng).to_bytes_be()
            ),
            Error::BadEncoding,
            "Raw buffer for `A` is all 0xA",
        ),
        (
            concat_3!(
                &vec![0xF; OCTET_POINT_G1_LENGTH],
                Scalar::random(&mut OsRng).to_bytes_be(),
                Scalar::random(&mut OsRng).to_bytes_be()
            ),
            Error::BadEncoding,
            "Raw buffer for `A` is all 0xF",
        ),
        (
            concat_3!(
                G1Projective::random(&mut OsRng).to_affine().to_compressed(),
                &vec![0x0; OCTET_SCALAR_LENGTH],
                Scalar::random(&mut OsRng).to_bytes_be()
            ),
            Error::UnexpectedZeroValue,
            "Raw buffer for `e` is all zeroes",
        ),
        (
            concat_3!(
                G1Projective::random(&mut OsRng).to_affine().to_compressed(),
                &vec![0xFF; OCTET_SCALAR_LENGTH],
                Scalar::random(&mut OsRng).to_bytes_be()
            ),
            Error::MalformedSignature {
                cause: "failed to deserialize `e` component of signature"
                    .to_owned(),
            },
            "Raw buffer value for `e` is larger than modulus",
        ),
        (
            concat_3!(
                G1Projective::random(&mut OsRng).to_affine().to_compressed(),
                Scalar::random(&mut OsRng).to_bytes_be(),
                &vec![0x0; OCTET_SCALAR_LENGTH]
            ),
            Error::UnexpectedZeroValue,
            "Raw buffer for `s` is all zeroes",
        ),
        (
            concat_3!(
                G1Projective::random(&mut OsRng).to_affine().to_compressed(),
                Scalar::random(&mut OsRng).to_bytes_be(),
                &vec![0xFF; OCTET_SCALAR_LENGTH]
            ),
            Error::MalformedSignature {
                cause: "failed to deserialize `s` component of signature"
                    .to_owned(),
            },
            "Raw buffer value for `s` is larger than modulus",
        ),
        (
            concat_a_e_s!(
                G1Projective::identity(),
                Scalar::random(&mut OsRng),
                Scalar::random(&mut OsRng)
            ),
            Error::PointIsIdentity,
            "`A` is identity",
        ),
        (
            concat_a_e_s!(
                G1Projective::random(&mut OsRng),
                Scalar::zero(),
                Scalar::random(&mut OsRng)
            ),
            Error::UnexpectedZeroValue,
            "`e` is zero",
        ),
        (
            concat_a_e_s!(
                G1Projective::random(&mut OsRng),
                Scalar::zero(),
                Scalar::random(&mut OsRng)
            ),
            Error::UnexpectedZeroValue,
            "`e` is zero",
        ),
        (
            concat_a_e_s!(
                G1Projective::random(&mut OsRng),
                Scalar::random(&mut OsRng),
                Scalar::zero()
            ),
            Error::UnexpectedZeroValue,
            "`s` is zero",
        ),
    ];

    for (octets, error, failure_debug_message) in test_data {
        let result = Signature::from_octets(octets);
        assert_eq!(
            result,
            Err(error),
            "`Signature::from_octets` should fail - {}",
            failure_debug_message
        );
    }
}

#[test]
fn to_from_octets() {
    let mut signature = Signature::default();
    signature.A = G1Projective::random(&mut OsRng);
    signature.e = Scalar::random(&mut OsRng);
    signature.s = Scalar::random(&mut OsRng);

    let signature_from_octets = Signature::from_octets(&signature.to_octets())
        .expect("roundtrip `Signature::from_octets(...)` should not fail");
    assert_eq!(signature, signature_from_octets);
}
