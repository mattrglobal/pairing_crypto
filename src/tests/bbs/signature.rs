use super::{
    create_generator_helper,
    EXPECTED_SIGS,
    KEY_GEN_SEED,
    TEST_CLAIMS,
    TEST_HEADER,
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
};
use core::convert::TryFrom;
use ff::Field;
use group::Group;
use subtle::{Choice, ConditionallySelectable};

#[test]
fn sign_verify_e2e_nominal() {
    let test_atts = TEST_CLAIMS
        .iter()
        .map(|b| {
            Message::from_arbitrary_data(
                b.as_ref(),
                MAP_MESSAGE_TO_SCALAR_DST.as_ref(),
            )
        })
        .collect::<Result<Vec<Message>, _>>()
        .expect("claims to `Message` conversion failed");

    for i in 0..TEST_KEY_INFOS.len() {
        let sk =
            SecretKey::new(KEY_GEN_SEED.as_ref(), TEST_KEY_INFOS[i].as_ref())
                .expect("secret key generation failed");
        let pk = PublicKey::from(&sk);
        let gens = create_generator_helper(test_atts.len());
        let signature =
            Signature::new(&sk, &pk, Some(&TEST_HEADER), &gens, &test_atts)
                .expect("signing failed");
        // println!("{:?},", hex::encode(signature.to_octets()));

        assert_eq!(
            signature
                .verify(&pk, Some(&TEST_HEADER), &gens, &test_atts)
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
