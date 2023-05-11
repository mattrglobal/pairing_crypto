use super::{
    create_generators_helper,
    get_expected_signature,
    ANOTHER_TEST_HEADER,
    EXPECTED_SIGNATURES,
    TEST_HEADER,
    TEST_KEY_GEN_IKM,
    TEST_KEY_INFO,
    TEST_KEY_INFOS,
};
use crate::{
    bbs::{
        ciphersuites::{
            bls12_381::{PublicKey, SecretKey},
            bls12_381_g1_shake_256::Bls12381Shake256CipherSuiteParameter,
        },
        core::{
            generator::Generators,
            key_pair::KeyPair,
            signature::Signature,
            types::Message,
        },
    },
    common::util::vec_to_byte_array,
    curves::bls12_381::{
        G1Projective,
        Scalar,
        OCTET_POINT_G1_LENGTH,
        OCTET_SCALAR_LENGTH,
    },
    tests::bbs::{
        get_random_test_key_pair,
        get_test_messages,
        test_generators_random_message_generators,
        test_generators_random_q,
        EXPECTED_SIGNATURE,
        EXPECTED_SIGNATURE_NO_HEADER,
    },
    Error,
};
use core::convert::TryFrom;
use ff::Field;
use group::{Curve, Group};
use rand_core::OsRng;
use std::vec;
use subtle::{Choice, ConditionallySelectable};

#[test]
fn debug_display() {
    let signature = Signature {
        A: G1Projective::identity(),
        e: Scalar::one(),
    };

    assert_eq!(format!("{:?}", signature), "Signature { A: G1Projective { x: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), y: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000), z: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000) }, e: Scalar(0x0000000000000000000000000000000000000000000000000000000000000001) }");
    assert_eq!(format!("{}", signature), "Signature(A: 0xc00x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x00, e: Scalar(0x0000000000000000000000000000000000000000000000000000000000000001))");
}

#[test]
fn sign_verify_serde_nominal() {
    let key_pair = get_random_test_key_pair();
    let header = Some(&TEST_HEADER);
    let messages = get_test_messages();
    let generators = create_generators_helper(messages.len());

    let signature =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            header,
            &generators,
            &messages,
        )
        .expect("signing failed");

    assert!(signature
        .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.public_key,
            header,
            &generators,
            &messages
        )
        .expect("verification failed"),);

    let signature_octets = signature.to_octets();
    let signature_from_deserialization =
        Signature::from_octets(&signature_octets)
            .expect("signature deserialization failed");
    assert_eq!(
        signature, signature_from_deserialization,
        "signature serde failed"
    );

    assert!(signature_from_deserialization
        .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.public_key,
            header,
            &generators,
            &messages
        )
        .expect("signature verification failed after serde"),);
}

#[test]
fn sign_verify_no_header() {
    let sk = SecretKey::new(TEST_KEY_GEN_IKM, TEST_KEY_INFO)
        .expect("key generation failed");
    let pk = PublicKey::from(&sk);
    let messages = get_test_messages();
    let generators = create_generators_helper(messages.len());

    let signature = Signature::new::<
        _,
        _,
        _,
        Bls12381Shake256CipherSuiteParameter,
    >(&sk, &pk, None::<&[u8]>, &generators, &messages)
    .expect("signing failed");

    // println!("signature no header = {:?}",
    // hex::encode(signature.to_octets()));

    let expected_signature =
        get_expected_signature(EXPECTED_SIGNATURE_NO_HEADER);
    assert_eq!(signature, expected_signature);

    assert!(signature
        .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &pk,
            None::<&[u8]>,
            &generators,
            &messages
        )
        .expect("verification failed"),);
}

#[test]
fn sign_verify_different_key_infos() {
    let messages = get_test_messages();

    for i in 0..TEST_KEY_INFOS.len() {
        let sk = SecretKey::new(TEST_KEY_GEN_IKM, TEST_KEY_INFOS[i])
            .expect("secret key generation failed");
        let pk = PublicKey::from(&sk);
        let generators = create_generators_helper(messages.len());
        let signature = Signature::new::<
            _,
            _,
            _,
            Bls12381Shake256CipherSuiteParameter,
        >(
            &sk, &pk, Some(&TEST_HEADER), &generators, &messages
        )
        .expect("signing failed");
        // println!("{:?},", hex::encode(signature.to_octets()));

        assert!(signature
            .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                &pk,
                Some(&TEST_HEADER),
                &generators,
                &messages
            )
            .unwrap());
        let expected_signature_i =
            get_expected_signature(EXPECTED_SIGNATURES[i]);
        assert_eq!(signature, expected_signature_i);
    }
}

#[test]
fn signature_equality() {
    let key_pair = get_random_test_key_pair();
    let header = Some(&TEST_HEADER);
    let messages = get_test_messages();
    let generators = create_generators_helper(messages.len());

    let signature1 =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            header,
            &generators,
            &messages,
        )
        .expect("signing failed");

    let signature2 =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
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

    let signature5 =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
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
fn signature_uniqueness() {
    let key_pair1 = get_random_test_key_pair();
    let key_pair2 = get_random_test_key_pair();

    let header = Some(TEST_HEADER.as_ref());
    let another_header = Some(ANOTHER_TEST_HEADER.as_ref());
    let messages = get_test_messages();
    let generators = create_generators_helper(messages.len());

    let test_data = [
        (
            (
                &key_pair1.secret_key,
                &key_pair1.public_key,
                header,
                &generators,
                &messages,
            ),
            (
                &key_pair2.secret_key,
                &key_pair2.public_key,
                header,
                &generators,
                &messages,
            ),
            "different key-pairs",
        ),
        (
            (
                &key_pair1.secret_key,
                &key_pair1.public_key,
                header,
                &generators,
                &messages,
            ),
            (
                &key_pair1.secret_key,
                &key_pair1.public_key,
                another_header,
                &generators,
                &messages,
            ),
            "different headers",
        ),
        (
            (
                &key_pair1.secret_key,
                &key_pair1.public_key,
                header,
                &create_generators_helper(0),
                &vec![],
            ),
            (
                &key_pair1.secret_key,
                &key_pair1.public_key,
                another_header,
                &create_generators_helper(0),
                &vec![],
            ),
            "different headers, empty messages",
        ),
        (
            (
                &key_pair1.secret_key,
                &key_pair1.public_key,
                header,
                &generators,
                &messages,
            ),
            (
                &key_pair1.secret_key,
                &key_pair1.public_key,
                header,
                &generators,
                &vec![Message::random(&mut OsRng); 6],
            ),
            "different messages",
        ),
    ];

    for (
        (sk1, pk1, h1, gen1, msg1),
        (sk2, pk2, h2, gen2, msg2),
        failure_debug_message,
    ) in test_data
    {
        let signature1 =
            Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                sk1, pk1, h1, gen1, msg1,
            )
            .expect("signature1 creation failed");

        let signature2 =
            Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                sk2, pk2, h2, gen2, msg2,
            )
            .expect("signature2 creation failed");

        assert_ne!(
            signature1, signature2,
            "both signatures should be unique - {}",
            failure_debug_message
        );
    }
}

#[test]
fn sign_verify_valid_cases() {
    let sk = SecretKey::random(&mut OsRng, TEST_KEY_INFO)
        .expect("secret key generation failed");
    let pk = PublicKey::from(&sk);
    let header = Some(&TEST_HEADER);
    let messages = get_test_messages();
    let generators = create_generators_helper(messages.len());

    // [(SK, PK, header, generators, messages, failure-debug-message)]
    let test_data = [
        (
            &sk,
            &pk,
            header,
            &create_generators_helper(0),
            &vec![],
            "valid header, no messages and no message-generators are provided",
        ),
        (
            &sk,
            &pk,
            None,
            &generators,
            &messages,
            "no header, but equal no. of messages and message-generators are \
             provided",
        ),
    ];

    for (sk, pk, header, generators, messages, failure_debug_message) in
        test_data
    {
        let signature =
            Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                sk, pk, header, generators, &messages,
            )
            .unwrap_or_else(|_| {
                panic!("signing should pass - {failure_debug_message}")
            });
        assert!(signature
            .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                pk, header, generators, &messages
            )
            .unwrap_or_else(|_| panic!(
                "verification should pass - {failure_debug_message}"
            )),);
    }

    // Public key validity is not checked during signing
    Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
        &sk,
        &PublicKey::default(),
        header,
        &generators,
        &messages,
    )
    .expect(
        "signing should pass - public key validity is not checked during \
         signing",
    );
}

#[test]
// Test `Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(...)`
// implementation's returned errors by passing invalid paramter values.
fn signature_new_invalid_parameters() {
    let sk = SecretKey::random(&mut OsRng, TEST_KEY_INFO)
        .expect("secret key generation failed");
    let pk = PublicKey::from(&sk);
    let header = Some(&TEST_HEADER);
    let messages = get_test_messages();
    let generators = create_generators_helper(messages.len());
    // Just to make sure sign-verify succeeds with above valid values
    let signature = Signature::new::<
        _,
        _,
        _,
        Bls12381Shake256CipherSuiteParameter,
    >(&sk, &pk, header, &generators, &messages)
    .expect("signing failed");
    assert!(signature
        .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &pk,
            header,
            &generators,
            &messages
        )
        .expect("verification failed"),);

    // [(SK, PK, header, generators, messages, result, failure-debug-message)]
    let test_data = [
        (
            &sk,
            &pk,
            None,
            &create_generators_helper(0),
            &vec![],
            Error::BadParams {
                cause: "nothing to sign".to_owned(),
            },
            "no header, no messages, no generators",
        ),
        (
            &SecretKey::default(),
            &pk,
            None,
            &generators,
            &vec![],
            Error::BadParams {
                cause: "nothing to sign".to_owned(),
            },
            "no header, no messages but message-generators are provided",
        ),
        (
            &SecretKey::default(),
            &pk,
            None,
            &create_generators_helper(0),
            &messages,
            Error::MessageGeneratorsLengthMismatch {
                generators: 0,
                messages: messages.len(),
            },
            "no header, no message-generators but messages are provided",
        ),
        (
            &SecretKey::default(),
            &pk,
            None,
            &generators,
            &vec![Message::default(); 2],
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: 2,
            },
            "no header, more message-generators than messages",
        ),
        (
            &SecretKey::default(),
            &pk,
            None,
            &create_generators_helper(2),
            &messages,
            Error::MessageGeneratorsLengthMismatch {
                generators: 2,
                messages: messages.len(),
            },
            "no header, more messages than message-generators",
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
            "valid header, no message-generators but messages are provided",
        ),
        (
            &SecretKey::default(),
            &pk,
            header,
            &generators,
            &vec![],
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: 0,
            },
            "valid header, no messages but message-generators are provided",
        ),
        (
            &SecretKey::default(),
            &pk,
            header,
            &generators,
            &vec![Message::default(); 2],
            Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: 2,
            },
            "valid header, more message-generators than messages",
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
            "valid header, more messages than message-generators",
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
        let result =
            Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                sk, pk, header, generators, &messages,
            );
        assert_eq!(
            result,
            Err(error),
            "signing should fail - {}",
            failure_debug_message
        );
    }
}

#[test]
// Test that `Signature::verify()` fails with tampered signature components.
fn verify_tampered_signature() {
    let key_pair = get_random_test_key_pair();
    let header = Some(TEST_HEADER.as_ref());
    let messages = get_test_messages();
    let generators = create_generators_helper(messages.len());

    // Just to make sure sign-verify succeeds with above valid values
    let signature =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            header,
            &generators,
            &messages,
        )
        .expect("signing failed");
    assert!(signature
        .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.public_key,
            header,
            &generators,
            &messages
        )
        .expect("verification failed"),);

    let mut tampered_signature = signature;
    tampered_signature.A = G1Projective::random(&mut OsRng);
    assert!(
        !tampered_signature
            .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                &key_pair.public_key,
                header,
                &generators,
                &messages
            )
            .expect("verification should not fail with error"),
        "verification should fail with tampered `A` value"
    );

    tampered_signature = signature;
    tampered_signature.e = Scalar::random(&mut OsRng);
    assert!(
        !tampered_signature
            .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                &key_pair.public_key,
                header,
                &generators,
                &messages
            )
            .expect("verification should not fail with error"),
        "verification should fail with tampered `e` value"
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
    let key_pair = get_random_test_key_pair();
    let header = Some(TEST_HEADER.as_ref());
    let generators = create_generators_helper(messages.len());

    // Just to make sure sign-verify succeeds with above valid values
    let signature =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            header,
            &generators,
            &messages,
        )
        .expect("signing failed");
    assert!(signature
        .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.public_key,
            header,
            &generators,
            &messages
        )
        .expect("verification failed"),);

    // Another set of variables to be used as tampered values
    let different_key_pair = KeyPair::random(&mut OsRng, TEST_KEY_INFO)
        .expect("key pair generation failed");
    let different_header = Some(b"another-set-of-header".as_ref());
    let generators_different_q = test_generators_random_q(messages.len());
    let generators_different_message_generators =
        test_generators_random_message_generators(messages.len());
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
            &generators_different_q,
            &messages,
            "different Q value of generators",
        ),
        (
            &key_pair.public_key,
            header,
            &generators_different_message_generators,
            &messages,
            "different message generators",
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
                generators.message_generators_length()
            ],
            "all messages are different",
        ),
    ];

    for (pk, header, generators, messages, failure_debug_message) in test_data {
        let result = signature
            .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                pk, header, generators, &messages,
            )
            .expect("verify should return a true/false value, not error");
        assert!(
            !result,
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
                .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                    pk, header, generators, &messages,
                )
                .expect("verify should return a true/false value, not error");
            assert!(
                !result,
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
    verify_tampered_signature_parameters_helper(get_test_messages());
}

#[test]
// Test as above test case `verify_tampered_signature_parameters` but here
// original signature is produced with `header` being `None`.
fn verify_tampered_signature_parameters_no_header_signature() {
    let key_pair = get_random_test_key_pair();
    let header = None;
    let messages = get_test_messages();
    let generators = create_generators_helper(messages.len());

    // Just to make sure sign-verify succeeds with above valid values
    let signature =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            header,
            &generators,
            &messages,
        )
        .expect("signing failed");
    assert!(signature
        .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.public_key,
            header,
            &generators,
            &messages
        )
        .expect("verification failed"),);

    // Another set of variables to be used as tampered values
    let different_key_pair = KeyPair::random(&mut OsRng, TEST_KEY_INFO)
        .expect("key pair generation failed");
    let different_header = Some(b"another-set-of-header".as_ref());
    let generators_different_q = test_generators_random_q(messages.len());
    let generators_different_message_generators =
        test_generators_random_message_generators(messages.len());

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
            &generators_different_q,
            &messages,
            "different Q value of generators",
        ),
        (
            &key_pair.public_key,
            header,
            &generators_different_message_generators,
            &messages,
            "different message generators",
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
                generators.message_generators_length()
            ],
            "all messages are different",
        ),
    ];

    for (pk, header, generators, messages, failure_debug_message) in test_data {
        let result = signature
            .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                pk, header, generators, &messages,
            )
            .expect("verify should return a true/false value, not error");
        assert!(
            !result,
            "verification should fail - {}",
            failure_debug_message
        );
    }
}

#[test]
// Test as above test case `verify_tampered_signature_parameters` but here
// original signature is produced with no messages.
fn verify_tampered_signature_parameters_no_messages_signature() {
    let key_pair = get_random_test_key_pair();
    let header = Some(TEST_HEADER.as_ref());
    let messages = vec![];
    let generators = create_generators_helper(messages.len());

    // Just to make sure sign-verify succeeds with above valid values
    let signature =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.secret_key,
            &key_pair.public_key,
            header,
            &generators,
            &messages,
        )
        .expect("signing failed");
    assert!(signature
        .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &key_pair.public_key,
            header,
            &generators,
            &messages
        )
        .expect("verification failed"));

    // Another set of variables to be used as tampered values
    let different_key_pair = KeyPair::random(&mut OsRng, TEST_KEY_INFO)
        .expect("key pair generation failed");
    let different_header = Some(b"another-set-of-header".as_ref());
    let generators_different_q = test_generators_random_q(messages.len());
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
            &generators_different_q,
            &messages,
            "different Q value of generators",
        ),
    ];

    for (pk, header, generators, messages, failure_debug_message) in test_data {
        let result = signature
            .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                pk, header, generators, &messages,
            )
            .expect("verify should return a true/false value, not error");
        assert!(
            !result,
            "verification should fail - {}",
            failure_debug_message
        );
    }
}

#[test]
fn verify_invalid_parameters() {
    let sk = SecretKey::random(&mut OsRng, TEST_KEY_INFO)
        .expect("secret key generation failed");
    let pk = PublicKey::from(&sk);
    let header = Some(&TEST_HEADER);
    let messages = get_test_messages();
    let generators = create_generators_helper(messages.len());
    // Just to make sure sign-verify succeeds with above valid values
    let signature = Signature::new::<
        _,
        _,
        _,
        Bls12381Shake256CipherSuiteParameter,
    >(&sk, &pk, header, &generators, &messages)
    .expect("signing failed");
    assert!(signature
        .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
            &pk,
            header,
            &generators,
            &messages
        )
        .expect("verification failed"));

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
                generators: generators.message_generators_length(),
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
                generators: generators.message_generators_length(),
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
        let result = signature
            .verify::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
                pk, header, generators, &messages,
            );
        assert_eq!(
            result,
            Err(error),
            "verification should fail - {}",
            failure_debug_message
        );
    }
}

// Concat `A` and `e` component of `Signature` as `Vec`.
macro_rules! concat_a_e {
    ($a:expr, $e:expr) => {
        [
            $a.to_affine().to_compressed().as_ref(),
            $e.to_bytes_be().as_ref(),
        ]
        .concat()
    };
}

#[test]
fn to_octets() {
    let key_pair = KeyPair::new(TEST_KEY_GEN_IKM, TEST_KEY_INFO)
        .expect("key pair generation failed");
    let header = Some(&TEST_HEADER);
    let messages = get_test_messages();
    let generators = create_generators_helper(messages.len());

    let mut signature =
        Signature::new::<_, _, _, Bls12381Shake256CipherSuiteParameter>(
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
    // println!("{:?},", hex::encode(signature_octets));
    assert_eq!(signature_octets, expected_signature_octets);

    let a = G1Projective::random(&mut OsRng);
    let e = Scalar::random(&mut OsRng);

    signature = Signature { A: a, e };
    signature_octets = signature.to_octets();
    let expected_signature_octets = [
        a.to_affine().to_compressed().as_ref(),
        e.to_bytes_be().as_ref(),
    ]
    .concat();
    assert_eq!(signature_octets, expected_signature_octets.as_slice());
}

// Concat 2 input buffers.
macro_rules! concat_2 {
    ($a:expr, $e:expr) => {
        [$a.as_ref(), $e.as_ref()].concat()
    };
}

#[test]
fn from_octets_invalid_parameters() {
    let test_data = [
        (
            vec![0x0; Signature::SIZE_BYTES],
            Error::BadEncoding,
            "input data is all zeroes",
        ),
        (
            concat_2!(
                &vec![0x0; OCTET_POINT_G1_LENGTH],
                Scalar::random(&mut OsRng).to_bytes_be()
            ),
            Error::BadEncoding,
            "Raw buffer for `A` is all zeroes",
        ),
        (
            concat_2!(
                &vec![0xA; OCTET_POINT_G1_LENGTH],
                Scalar::random(&mut OsRng).to_bytes_be()
            ),
            Error::BadEncoding,
            "Raw buffer for `A` is all 0xA",
        ),
        (
            concat_2!(
                &vec![0xF; OCTET_POINT_G1_LENGTH],
                Scalar::random(&mut OsRng).to_bytes_be()
            ),
            Error::BadEncoding,
            "Raw buffer for `A` is all 0xF",
        ),
        (
            concat_2!(
                G1Projective::random(&mut OsRng).to_affine().to_compressed(),
                &vec![0x0; OCTET_SCALAR_LENGTH]
            ),
            Error::UnexpectedZeroValue,
            "Raw buffer for `e` is all zeroes",
        ),
        (
            concat_2!(
                G1Projective::random(&mut OsRng).to_affine().to_compressed(),
                &vec![0xFF; OCTET_SCALAR_LENGTH]
            ),
            Error::MalformedSignature {
                cause: "failed to deserialize `e` component of signature"
                    .to_owned(),
            },
            "Raw buffer value for `e` is larger than modulus",
        ),
        (
            concat_a_e!(G1Projective::identity(), Scalar::random(&mut OsRng)),
            Error::PointIsIdentity,
            "`A` is identity",
        ),
        (
            concat_a_e!(G1Projective::random(&mut OsRng), Scalar::zero()),
            Error::UnexpectedZeroValue,
            "`e` is zero",
        ),
    ];

    for (octets, error, failure_debug_message) in test_data {
        let result = Signature::from_octets(
            &vec_to_byte_array::<{ Signature::SIZE_BYTES }>(&octets).unwrap(),
        );
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
    let signature = Signature {
        A: G1Projective::random(&mut OsRng),
        e: Scalar::random(&mut OsRng),
    };

    let signature_from_octets = Signature::from_octets(&signature.to_octets())
        .expect("roundtrip `Signature::from_octets(...)` should not fail");
    assert_eq!(signature, signature_from_octets);
}
