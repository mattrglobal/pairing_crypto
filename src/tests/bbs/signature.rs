use super::{
    create_generator_helper,
    EXPECTED_SIGS,
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
        core::generator::Generators,
    },
    curves::bls12_381::{G1Projective, Scalar},
    Error,
};
use core::convert::TryFrom;
use ff::Field;
use group::Group;
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
fn sign_verify_e2e_nominal() {
    let messages = create_messages_helper();

    for i in 0..TEST_KEY_INFOS.len() {
        let sk = SecretKey::new(
            TEST_KEY_GEN_IKM.as_ref(),
            TEST_KEY_INFOS[i].as_ref(),
        )
        .expect("secret key generation failed");
        let pk = PublicKey::from(&sk);
        let generators = create_generator_helper(messages.len());
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
                hex::decode(EXPECTED_SIGS[i]).expect("hex decoding failed"),
            )
            .expect("data conversion failed"),
        )
        .expect("signature deserialization failed");
        assert_eq!(signature, expected_signature);
    }
}

#[test]
fn signature_new_valid_cases() {
    let sk = SecretKey::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("secret key generation failed");
    let pk = PublicKey::from(&sk);
    let header = Some(&TEST_HEADER);
    let messages = create_messages_helper();
    let generators = create_generator_helper(messages.len());

    // [(SK, PK, header, generators, messages, failure-debug-message)]
    let test_data = [
        (
            &sk,
            &pk,
            header,
            &create_generator_helper(0),
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
fn signature_new_error_cases() {
    let sk = SecretKey::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("secret key generation failed");
    let pk = PublicKey::from(&sk);
    let header = Some(&TEST_HEADER);
    let messages = create_messages_helper();
    let generators = create_generator_helper(messages.len());

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
            &create_generator_helper(0),
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
            &create_generator_helper(2),
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
fn serialization() {
    let mut sig = Signature::default();
    sig.A = G1Projective::generator();
    sig.e = Scalar::one();
    sig.s = Scalar::one() + Scalar::one();

    let sig_clone = Signature::from_octets(&sig.to_octets());
    assert_eq!(sig_clone.is_ok(), true);
    let sig2 = sig_clone.unwrap();
    assert_eq!(sig, sig2);
    sig.A = G1Projective::identity();
    sig.conditional_assign(&sig2, Choice::from(1u8));
    assert_eq!(sig, sig2);
}

#[test]
fn invalid_signature() {
    let sig = Signature::default();
    let pk = PublicKey::default();
    let sk = SecretKey::default();
    let msgs = [Message::default(), Message::default()];
    let generators =
        Generators::new(&[], &[], &[], 1).expect("generators creation failed");
    assert!(Signature::new(&sk, &pk, Some(&[]), &generators, &msgs).is_err());
    assert!(sig.verify(&pk, Some(&[]), &generators, &msgs).is_err());
    let generators =
        Generators::new(&[], &[], &[], 3).expect("generators creation failed");
    assert!(sig.verify(&pk, Some(&[]), &generators, &msgs).is_err());
    assert!(Signature::new(&sk, &pk, Some(&[]), &generators, &msgs).is_err());
}
