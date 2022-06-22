use crate::{
    bbs::core::{
        constants::MIN_KEY_GEN_IKM_LENGTH,
        key_pair::{KeyPair, PublicKey, SecretKey},
    },
    Error,
};
use core::convert::TryFrom;
use rand_core::OsRng;

const TEST_IKM: &[u8; 48] = b"this-IS-just-an-Test-IKM-to-generate-$e(r@t#-key";
const TEST_KEY_INFO: &[u8; 52] =
    b"this-IS-some-key-metadata-to-be-used-in-test-key-gen";
const EXPECTED_TEST_SECRET_KEY: &[u8; 64] =
    b"47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56";
const EXPECTED_TEST_PUBLIC_KEY: &[u8; 192] = b"b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7";

#[test]
fn nominal() {
    // Secret key gen from IKM
    let sk = SecretKey::new(TEST_IKM.as_ref(), TEST_KEY_INFO.as_ref())
        .expect("secret key gen from IKM failed");

    // Generate public key from secret key
    let pk = PublicKey::from(&sk);
    assert_eq!(pk.is_valid().unwrap_u8(), 1, "generated public is invalid");

    // Secret key gen from Rng
    let sk = SecretKey::random(&mut OsRng::default(), TEST_KEY_INFO.as_ref())
        .expect("random secret key gen failed");

    // Generate public key from secret key
    let pk = PublicKey::from(&sk);
    assert_eq!(pk.is_valid().unwrap_u8(), 1, "generated public is invalid");

    // Key pair gen from IKM
    let KeyPair {
        secret_key: _,
        public_key: pk,
    } = KeyPair::new(TEST_IKM.as_ref(), TEST_KEY_INFO.as_ref())
        .expect("key pair generation failed");
    assert_eq!(pk.is_valid().unwrap_u8(), 1, "generated public is invalid");

    // Key pair gen from Rng
    let KeyPair {
        secret_key: _,
        public_key: pk,
    } = KeyPair::random(&mut OsRng::default(), TEST_KEY_INFO.as_ref())
        .expect("random key pair generation failed");
    assert_eq!(pk.is_valid().unwrap_u8(), 1, "generated public is invalid");
}

#[test]
fn key_gen_expected_values() {
    // Secret key gen from IKM
    let sk = SecretKey::new(TEST_IKM.as_ref(), TEST_KEY_INFO.as_ref())
        .expect("secret key gen from IKM failed");
    let pk = PublicKey::from(&sk);
    assert_eq!(
        sk.to_bytes().to_vec(),
        hex::decode(EXPECTED_TEST_SECRET_KEY).unwrap(),
        "generated secret key value doesn't match to expected value"
    );
    assert_eq!(
        pk.point_to_octets().to_vec(),
        hex::decode(EXPECTED_TEST_PUBLIC_KEY).unwrap(),
        "generated public key value doesn't match to expected value"
    );

    // Key pair gen from IKM
    let KeyPair {
        secret_key: sk,
        public_key: pk,
    } = KeyPair::new(TEST_IKM.as_ref(), TEST_KEY_INFO.as_ref())
        .expect("key pair generation failed");
    assert_eq!(
        sk.to_bytes().to_vec(),
        hex::decode(EXPECTED_TEST_SECRET_KEY).unwrap(),
        "generated secret key value doesn't match to expected value"
    );
    assert_eq!(
        pk.point_to_octets().to_vec(),
        hex::decode(EXPECTED_TEST_PUBLIC_KEY).unwrap(),
        "generated public key value doesn't match to expected value"
    );

    println!("sk: {:?}", hex::encode(sk.to_bytes()));
    println!("pk: {:?}", hex::encode(&pk.point_to_octets()));
}

#[test]
fn key_gen_short_ikm() {
    let ikm = [0u8; MIN_KEY_GEN_IKM_LENGTH - 1];

    // Secret key gen from IKM
    let sk = SecretKey::new(ikm.as_ref(), TEST_KEY_INFO.as_ref());
    assert!(sk.is_none(), "`SecretKey` should be a `None` value");

    // Key pair gen from IKM
    let key_pair = KeyPair::new(ikm.as_ref(), TEST_KEY_INFO.as_ref());
    assert!(key_pair.is_none(), "`KeyPair` should be a `None` value");
}

#[test]
fn key_gen_from_erroneous_rng() {
    // An erroneous Rng
    #[derive(Default)]
    struct ErroneousRng;
    impl rand_core::CryptoRng for ErroneousRng {}

    impl rand_core::RngCore for ErroneousRng {
        fn next_u32(&mut self) -> u32 {
            todo!()
        }

        fn next_u64(&mut self) -> u64 {
            todo!()
        }

        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            todo!()
        }

        // Return error
        fn try_fill_bytes(
            &mut self,
            _dest: &mut [u8],
        ) -> Result<(), rand::Error> {
            return Err(rand::Error::new(Error::CryptoOps {
                cause: "rng error".to_owned(),
            }));
        }
    }

    // Secret key gen from erroneous Rng
    let sk =
        SecretKey::random(&mut ErroneousRng::default(), TEST_KEY_INFO.as_ref());
    assert!(sk.is_none(), "`SecretKey` should be a `None` value");

    // Key pair gen from erroneous Rng
    let key_pair =
        KeyPair::random(&mut ErroneousRng::default(), TEST_KEY_INFO.as_ref());
    assert!(key_pair.is_none(), "`KeyPair` should be a `None` value");
}

#[test]
fn secret_key_serde() {
    let expected_sk_u8_array = <[u8; SecretKey::SIZE_BYTES]>::try_from(
        hex::decode(EXPECTED_TEST_SECRET_KEY).unwrap(),
    )
    .unwrap();
    let expected_sk_vec = hex::decode(EXPECTED_TEST_SECRET_KEY).unwrap();

    let sk = SecretKey::new(TEST_IKM.as_ref(), TEST_KEY_INFO.as_ref())
        .expect("secret key generation failed");

    // <[u8; SecretKey::SIZE_BYTES]>::from(SecretKey)
    assert_eq!(
        <[u8; SecretKey::SIZE_BYTES]>::from(sk),
        expected_sk_u8_array,
        "`<[u8; SecretKey::SIZE_BYTES]>::from(SecretKey)` conversion mismatch"
    );

    // <[u8; SecretKey::SIZE_BYTES]>::from(&SecretKey)
    assert_eq!(
        <[u8; SecretKey::SIZE_BYTES]>::from(&sk),
        expected_sk_u8_array,
        "`<[u8; SecretKey::SIZE_BYTES]>::from(&SecretKey)` conversion mismatch"
    );

    // SecretKey::to_bytes
    assert_eq!(
        sk.to_bytes(),
        expected_sk_u8_array,
        "`SecretKey::to_bytes` conversion mismatch"
    );

    // SecretKey::from_bytes
    let sk_from_bytes = SecretKey::from_bytes(&expected_sk_u8_array)
        .expect("`SecretKey::from_bytes` deserialization failed");
    assert_eq!(
        sk_from_bytes, sk,
        "`SecretKey::from_bytes` conversion mismatch"
    );

    // SecretKey::from_vec
    let sk_from_vec = SecretKey::from_vec(expected_sk_vec.clone())
        .expect("`SecretKey::from_vec` deserialization failed");
    assert_eq!(sk_from_vec, sk, "`SecretKey::from_vec` conversion mismatch");
}

#[test]
fn public_key_serde() {
    let expected_pk_u8_array = <[u8; PublicKey::SIZE_BYTES]>::try_from(
        hex::decode(EXPECTED_TEST_PUBLIC_KEY).unwrap(),
    )
    .unwrap();
    let expected_pk_vec = hex::decode(EXPECTED_TEST_PUBLIC_KEY).unwrap();

    // Key pair gen from IKM
    let KeyPair {
        secret_key: _,
        public_key: pk,
    } = KeyPair::new(TEST_IKM.as_ref(), TEST_KEY_INFO.as_ref())
        .expect("key pair generation failed");

    // <[u8; PublicKey::SIZE_BYTES]>::from(PublicKey)
    assert_eq!(
        <[u8; PublicKey::SIZE_BYTES]>::from(pk),
        expected_pk_u8_array,
        "`<[u8; PublicKey::SIZE_BYTES]>::from(PublicKey)` conversion mismatch"
    );

    // <[u8; PublicKey::SIZE_BYTES]>::from(&PublicKey)
    assert_eq!(
        <[u8; PublicKey::SIZE_BYTES]>::from(&pk),
        expected_pk_u8_array,
        "`<[u8; PublicKey::SIZE_BYTES]>::from(&PublicKey)` conversion mismatch"
    );

    // PublicKey::point_to_octets
    assert_eq!(
        pk.point_to_octets(),
        expected_pk_u8_array,
        "`PublicKey::point_to_octets` conversion mismatch"
    );

    // PublicKey::octets_to_point
    let pk_from_octets = PublicKey::octets_to_point(&expected_pk_u8_array)
        .expect("`PublicKey::octets_to_point` deserialization failed");
    assert_eq!(
        pk_from_octets, pk,
        "`PublicKey::octets_to_point` conversion mismatch"
    );

    // PublicKey::from_vec
    let pk_from_vec = PublicKey::from_vec(expected_pk_vec)
        .expect("`PublicKey::from_vec` deserialization failed");
    assert_eq!(pk_from_vec, pk, "`PublicKey::from_vec` conversion mismatch");
}
