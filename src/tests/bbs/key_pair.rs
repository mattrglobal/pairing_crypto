use crate::{
    bbs::core::{
        constants::MIN_KEY_GEN_IKM_LENGTH,
        key_pair::{KeyPair, PublicKey, SecretKey},
    },
    curves::bls12_381::G2Projective,
    from_vec_deserialization_invalid_vec_size,
    Error,
};
use core::convert::TryFrom;
use ff::Field;
use group::{Curve, Group};
use rand_core::OsRng;
use zeroize::Zeroize;

const TEST_IKM: &[u8; 48] = b"this-IS-just-an-Test-IKM-to-generate-$e(r@t#-key";
const TEST_KEY_INFO: &[u8; 52] =
    b"this-IS-some-key-metadata-to-be-used-in-test-key-gen";
const EXPECTED_TEST_SECRET_KEY: &[u8; 64] =
    b"47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56";
const EXPECTED_TEST_PUBLIC_KEY: &[u8; 192] = b"b65b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7";

#[test]
fn debug_display() {
    // Secret key gen from IKM
    let sk = SecretKey::new(TEST_IKM, TEST_KEY_INFO)
        .expect("secret key gen from IKM failed");

    // Generate public key from secret key
    let pk = PublicKey::from(&sk);

    assert_eq!(format!("{:?}", pk), "PublicKey(G2Projective { x: Fp2 { c0: Fp(0x159c155fc3841a9ad4045e37161c9f0d9a4f361b93cfdc67d365f3be1a398e56aa173d7a55e01b4a8dd2494e7fb90da7), c1: Fp(0x165b7cbff4e81b723456a13936b6bcc77a078bf6291765f3ae13170072249dd7daa7ec1bd82b818ab60198030b45b8fa) }, y: Fp2 { c0: Fp(0x05201d3d9156e676c12b9b8c90bc650d2df4c1f14a5f9c9d569b5856d1d0c81b292657cfc9c940e546e1d5c78eb12861), c1: Fp(0x0f797d03534669ce3a548b5857412de065a331d275e6011d075d24abcc84a2d9c19d8e8f8913a3d1f89ac1be66bd8e82) }, z: Fp2 { c0: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001), c1: Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000) } })");
    assert_eq!(format!("{}", pk), "PublicKey(0xb60x5b0x7c0xbf0xf40xe80x1b0x720x340x560xa10x390x360xb60xbc0xc70x7a0x070x8b0xf60x290x170x650xf30xae0x130x170x000x720x240x9d0xd70xda0xa70xec0x1b0xd80x2b0x810x8a0xb60x010x980x030x0b0x450xb80xfa0x150x9c0x150x5f0xc30x840x1a0x9a0xd40x040x5e0x370x160x1c0x9f0x0d0x9a0x4f0x360x1b0x930xcf0xdc0x670xd30x650xf30xbe0x1a0x390x8e0x560xaa0x170x3d0x7a0x550xe00x1b0x4a0x8d0xd20x490x4e0x7f0xb90x0d0xa7)");
}

#[test]
fn nominal() {
    // Secret key gen from IKM
    let sk = SecretKey::new(TEST_IKM, TEST_KEY_INFO)
        .expect("secret key gen from IKM failed");
    // Generate public key from secret key
    let pk = PublicKey::from(&sk);
    assert_eq!(
        pk.is_valid().unwrap_u8(),
        1,
        "generated public key is invalid"
    );

    // Secret key gen from IKM, no key-info
    let sk =
        SecretKey::new(TEST_IKM, &[]).expect("secret key gen from IKM failed");
    // Generate public key from secret key
    let pk = PublicKey::from(&sk);
    assert_eq!(
        pk.is_valid().unwrap_u8(),
        1,
        "generated public key is invalid"
    );

    // Secret key gen from Rng
    let sk = SecretKey::random(&mut OsRng::default(), TEST_KEY_INFO)
        .expect("random secret key gen failed");
    // Generate public key from secret key
    let pk = PublicKey::from(&sk);
    assert_eq!(
        pk.is_valid().unwrap_u8(),
        1,
        "generated public key is invalid"
    );

    // Secret key gen from Rng, no key-info
    let sk = SecretKey::random(&mut OsRng::default(), &[])
        .expect("random secret key gen failed");
    // Generate public key from secret key
    let pk = PublicKey::from(&sk);
    assert_eq!(
        pk.is_valid().unwrap_u8(),
        1,
        "generated public key is invalid"
    );

    // Key pair gen from IKM
    let KeyPair {
        secret_key: _,
        public_key: pk,
    } = KeyPair::new(TEST_IKM.as_ref(), TEST_KEY_INFO)
        .expect("key pair generation failed");
    assert_eq!(
        pk.is_valid().unwrap_u8(),
        1,
        "generated public key is invalid"
    );

    // Key pair gen from IKM, no key-info
    let KeyPair {
        secret_key: _,
        public_key: pk,
    } = KeyPair::new(TEST_IKM.as_ref(), &[])
        .expect("key pair generation failed");
    assert_eq!(
        pk.is_valid().unwrap_u8(),
        1,
        "generated public key is invalid"
    );

    // Key pair gen from Rng
    let KeyPair {
        secret_key: _,
        public_key: pk,
    } = KeyPair::random(&mut OsRng::default(), TEST_KEY_INFO)
        .expect("random key pair generation failed");
    assert_eq!(
        pk.is_valid().unwrap_u8(),
        1,
        "generated public key is invalid"
    );

    // Key pair gen from Rng, no key-info
    let KeyPair {
        secret_key: _,
        public_key: pk,
    } = KeyPair::random(&mut OsRng::default(), &[])
        .expect("random key pair generation failed");
    assert_eq!(
        pk.is_valid().unwrap_u8(),
        1,
        "generated public key is invalid"
    );
}

#[test]
fn key_gen_expected_values() {
    // Secret key gen from IKM
    let sk = SecretKey::new(TEST_IKM, TEST_KEY_INFO)
        .expect("secret key gen from IKM failed");
    let pk = PublicKey::from(&sk);
    assert_eq!(
        sk.to_bytes().to_vec(),
        hex::decode(EXPECTED_TEST_SECRET_KEY).unwrap(),
        "generated secret key value doesn't match to expected value"
    );
    assert_eq!(
        pk.to_octets().to_vec(),
        hex::decode(EXPECTED_TEST_PUBLIC_KEY).unwrap(),
        "generated public key value doesn't match to expected value"
    );

    // Key pair gen from IKM
    let key_pair = KeyPair::new(TEST_IKM, TEST_KEY_INFO)
        .expect("key pair generation failed");
    assert_eq!(
        key_pair.secret_key.to_bytes().to_vec(),
        hex::decode(EXPECTED_TEST_SECRET_KEY).unwrap(),
        "generated secret key value doesn't match to expected value"
    );
    assert_eq!(
        pk.to_octets().to_vec(),
        hex::decode(EXPECTED_TEST_PUBLIC_KEY).unwrap(),
        "generated public key value doesn't match to expected value"
    );
}

#[test]
fn key_gen_short_ikm() {
    let ikm = [0u8; MIN_KEY_GEN_IKM_LENGTH - 1];

    // Secret key gen from IKM
    let sk = SecretKey::new(ikm.as_ref(), TEST_KEY_INFO);
    assert!(sk.is_none(), "`SecretKey` should be a `None` value");

    // Key pair gen from IKM
    let key_pair = KeyPair::new(ikm.as_ref(), TEST_KEY_INFO);
    assert!(key_pair.is_none(), "`KeyPair` should be a `None` value");
}

#[test]
fn key_gen_equality_with_same_ikm_and_key_info() {
    // Secret key gen from IKM
    let sk1 = SecretKey::new(TEST_IKM, TEST_KEY_INFO)
        .expect("secret key gen from IKM failed");
    // Generate public key from secret key
    let pk1 = PublicKey::from(&sk1);
    let sk2 = SecretKey::new(TEST_IKM, TEST_KEY_INFO)
        .expect("secret key gen from IKM failed");
    // Generate public key from secret key
    let pk2 = PublicKey::from(&sk2);
    assert_eq!(sk1, sk2);
    assert_eq!(pk1, pk2);

    // Key pair gen from Rng
    let key_pair1 = KeyPair::new(TEST_IKM, TEST_KEY_INFO)
        .expect("random key pair generation failed");
    let key_pair2 = KeyPair::new(TEST_IKM, TEST_KEY_INFO)
        .expect("random key pair generation failed");
    assert_eq!(key_pair1.secret_key, key_pair2.secret_key);
    assert_eq!(key_pair1.public_key, key_pair2.public_key);

    // Key pair gen from Rng, no key-info
    let key_pair1 =
        KeyPair::new(TEST_IKM, &[]).expect("random key pair generation failed");
    let key_pair2 =
        KeyPair::new(TEST_IKM, &[]).expect("random key pair generation failed");
    assert_eq!(key_pair1.secret_key, key_pair2.secret_key);
    assert_eq!(key_pair1.public_key, key_pair2.public_key);
}

#[test]
fn key_gen_uniqueness() {
    let test_data = [
        (
            (
                b"test-ikm-11112222333344445555666677778888".as_ref(),
                b"test-key-info".as_ref(),
            ),
            (
                b"test-ikm-aaaabbbbccccddddeeeeffffgggghhhh".as_ref(),
                b"test-key-info".as_ref(),
            ),
            "different IKM, same key-info",
        ),
        (
            (b"test-ikm-11112222333344445555666677778888".as_ref(), &[]),
            (b"test-ikm-aaaabbbbccccddddeeeeffffgggghhhh".as_ref(), &[]),
            "different IKM, empty key-info",
        ),
        (
            (
                b"test-ikm-11112222333344445555666677778888".as_ref(),
                b"test-key-info-1".as_ref(),
            ),
            (
                b"test-ikm-11112222333344445555666677778888".as_ref(),
                b"test-key-info-2".as_ref(),
            ),
            "same IKM, different key-info",
        ),
    ];
    for ((ikm1, key_info_1), (ikm2, key_info_2), failure_debug_message) in
        test_data
    {
        // Using SecretKey API
        let sk1 = SecretKey::new(ikm1, key_info_1)
            .expect("first secret key gen from IKM failed");
        let pk1 = PublicKey::from(&sk1);
        let sk2 = SecretKey::new(ikm2, key_info_2)
            .expect("second secret key gen from IKM failed");
        let pk2 = PublicKey::from(&sk2);
        assert_ne!(
            sk1, sk2,
            "generated secret-key should be different - {}",
            failure_debug_message
        );
        assert_ne!(
            pk1, pk2,
            "generated public-key should be different - {}",
            failure_debug_message
        );

        let key_pair1 = KeyPair::new(ikm1, key_info_1)
            .expect("first key-pair gen from IKM failed");
        let key_pair2 = KeyPair::new(ikm2, key_info_2)
            .expect("second key-pair gen from IKM failed");
        assert_ne!(
            key_pair1.secret_key, key_pair2.secret_key,
            "generated secret-key should be different - {}",
            failure_debug_message
        );
        assert_ne!(
            key_pair1.public_key, key_pair2.public_key,
            "generated public-key should be different - {}",
            failure_debug_message
        );

        // Using KeyPair API
    }

    // Different Rng
    let sk1 = SecretKey::random(&mut OsRng::default(), TEST_KEY_INFO)
        .expect("secret key gen from IKM failed");
    let pk1 = PublicKey::from(&sk1);
    let sk2 = SecretKey::random(&mut OsRng::default(), TEST_KEY_INFO)
        .expect("secret key gen from IKM failed");
    let pk2 = PublicKey::from(&sk2);
    assert_ne!(sk1, sk2);
    assert_ne!(pk1, pk2);

    // KeyPair different Rng
    let key_pair1 = KeyPair::random(&mut OsRng::default(), TEST_KEY_INFO)
        .expect("random key pair generation failed");
    let key_pair2 = KeyPair::random(&mut OsRng::default(), TEST_KEY_INFO)
        .expect("random key pair generation failed");
    assert_ne!(key_pair1.secret_key, key_pair2.secret_key);
    assert_ne!(key_pair1.public_key, key_pair2.public_key);
}

#[test]
// Test whether keys generated using `SecretKey` and `PublicKey` APIs are equal
// to those generated using `KeyPair` APIs.
fn key_pair_sk_pk_api_consistency() {
    // Secret key gen from IKM
    let sk = SecretKey::new(TEST_IKM, TEST_KEY_INFO)
        .expect("secret key gen from IKM failed");

    // Generate public key from secret key
    let pk = PublicKey::from(&sk);

    // Key pair gen from IKM
    // Key pair gen from IKM
    let key_pair = KeyPair::new(TEST_IKM, TEST_KEY_INFO)
        .expect("key pair generation failed");
    let (key_pair_sk, key_pair_pk) =
        (key_pair.secret_key.clone(), key_pair.public_key);

    assert_eq!(sk, key_pair_sk);
    assert_eq!(pk, key_pair_pk);
}

#[test]
// Test error case check if `Rng` is erroneous.
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
            Err(rand::Error::new(Error::CryptoOps {
                cause: "rng error".to_owned(),
            }))
        }
    }

    // Secret key gen from erroneous Rng
    let sk = SecretKey::random(&mut ErroneousRng::default(), TEST_KEY_INFO);
    assert!(sk.is_none(), "`SecretKey` should be a `None` value");

    // Key pair gen from erroneous Rng
    let key_pair = KeyPair::random(&mut ErroneousRng::default(), TEST_KEY_INFO);
    assert!(key_pair.is_none(), "`KeyPair` should be a `None` value");
}

#[test]
fn secret_key_from_invalid_scalar_bytes() {
    assert_eq!(
        SecretKey::from_bytes(&[0x0; SecretKey::SIZE_BYTES]),
        Err(Error::InvalidSecretKey),
        "input data is all zeroes"
    );

    assert_eq!(
        SecretKey::from_bytes(&[0xFF; SecretKey::SIZE_BYTES]),
        Err(Error::BadParams {
            cause: "can't built a valid `SecretKey` from input data".to_owned()
        }),
        "input data value is greater than modulus"
    );
}

#[test]
fn public_key_from_invalid_bytes() {
    assert_eq!(
        PublicKey::from_octets(&[0x0; PublicKey::SIZE_BYTES]),
        Err(Error::BadEncoding),
        "input data is all zeroes"
    );

    assert_eq!(
        PublicKey::from_octets(&[0xFF; PublicKey::SIZE_BYTES]),
        Err(Error::BadEncoding),
        "input data is all '0xFF'"
    );
}

macro_rules! key_serde {
    ($key:ident, $key_type:ty, $expected_test_key:expr, $to_bytes_fn:ident, $from_bytes_fn:ident) => {
        let expected_key_u8_array = <[u8; <$key_type>::SIZE_BYTES]>::try_from(
            hex::decode($expected_test_key).unwrap(),
        )
        .unwrap();
        let expected_key_vec = hex::decode($expected_test_key).unwrap();
        assert_eq!(
            expected_key_vec.len(),
            <$key_type>::SIZE_BYTES,
            "invalid test key data vector size"
        );

        // For debug message
        let key_type_string = stringify!($key_type);

        // <[u8; $key_type::SIZE_BYTES]>::from(&$key_type)
        assert_eq!(
            <[u8; <$key_type>::SIZE_BYTES]>::from(&$key),
            expected_key_u8_array,
            "`<[u8; {key_type_string}::SIZE_BYTES]>::from(&\
             {key_type_string})` conversion failed"
        );

        // $key_type::$to_bytes_fn
        assert_eq!(
            $key.$to_bytes_fn(),
            expected_key_u8_array,
            "`{key_type_string}::$to_bytes_fn` conversion failed"
        );

        // $key_type::$from_bytes_fn
        let key_from_octets = <$key_type>::$from_bytes_fn(
            &expected_key_u8_array,
        )
        .expect("`{key_type_string}::$from_bytes_fn` deserialization failed");
        assert_eq!(
            key_from_octets, $key,
            "`{key_type_string}::$from_bytes_fn` conversion failed"
        );

        // $key_type::from_vec
        let key_from_vec = <$key_type>::from_vec(&expected_key_vec)
            .expect("`{key_type_string}::from_vec` deserialization failed");
        assert_eq!(
            key_from_vec, $key,
            "`{key_type_string}::from_vec` conversion failed"
        );
    };
}

#[test]
fn key_serde() {
    // Key pair gen from IKM
    let key_pair = KeyPair::new(TEST_IKM, TEST_KEY_INFO)
        .expect("key pair generation failed");
    let (sk, pk) = (key_pair.secret_key.clone(), key_pair.public_key);

    key_serde!(
        sk,
        SecretKey,
        EXPECTED_TEST_SECRET_KEY,
        to_bytes,
        from_bytes
    );

    key_serde!(
        pk,
        PublicKey,
        EXPECTED_TEST_PUBLIC_KEY,
        to_octets,
        from_octets
    );

    // <[u8; PublicKey::SIZE_BYTES]>::from(PublicKey)
    let expected_pk_u8_array = <[u8; PublicKey::SIZE_BYTES]>::try_from(
        hex::decode(EXPECTED_TEST_PUBLIC_KEY).unwrap(),
    )
    .unwrap();
    assert_eq!(
        <[u8; PublicKey::SIZE_BYTES]>::from(pk),
        expected_pk_u8_array,
        "`<[u8; PublicKey::SIZE_BYTES]>::from(PublicKey)` conversion mismatch"
    );
}

#[test]
fn from_vec_deserialization_invalid_vec_size() {
    let secret_key_expected_error_string = |data_len: usize| -> String {
        format!(
            "source vector size {data_len}, expected destination byte array \
             size {}",
            SecretKey::SIZE_BYTES,
        )
    };

    let public_key_expected_error_string = |data_len: usize| -> String {
        format!(
            "source vector size {data_len}, expected destination byte array \
             size of either {} or {}",
            PublicKey::SIZE_BYTES,
            PublicKey::SIZE_BYTES_UNCOMPRESSED
        )
    };

    from_vec_deserialization_invalid_vec_size!(
        SecretKey,
        secret_key_expected_error_string
    );
    from_vec_deserialization_invalid_vec_size!(
        PublicKey,
        public_key_expected_error_string
    );
}

#[test]
fn key_zeroize() {
    // Secret key gen from IKM
    let mut sk = SecretKey::new(TEST_IKM, TEST_KEY_INFO)
        .expect("secret key gen from IKM failed");
    assert_eq!(sk.0.is_zero().unwrap_u8(), 0u8);
    sk.zeroize();
    assert_eq!(sk.0.is_zero().unwrap_u8(), 1u8);

    // Key pair gen from Rng
    let mut key_pair = KeyPair::random(&mut OsRng::default(), TEST_KEY_INFO)
        .expect("random key pair generation failed");

    assert_eq!(key_pair.secret_key.0.is_zero().unwrap_u8(), 0u8);
    key_pair.zeroize();
    assert_eq!(key_pair.secret_key.0.is_zero().unwrap_u8(), 1u8);
}

#[test]
fn public_key_is_valid() {
    // PublicKey::default() is G2::Identity
    let pk = PublicKey::default();
    assert_eq!(pk.0.is_identity().unwrap_u8(), 1u8);
    assert_eq!(pk.is_valid().unwrap_u8(), 0u8);

    // Construct a PublicKey using G2::Generator
    let pk = PublicKey(G2Projective::generator());
    assert_eq!(pk.0.is_identity().unwrap_u8(), 0u8);
    assert_eq!(pk.0.to_affine().is_torsion_free().unwrap_u8(), 1u8);

    assert_eq!(pk.is_valid().unwrap_u8(), 1u8);
}

#[test]
fn test_secret_key_masked_debug_output() {
    // Secret key gen from IKM
    let sk = SecretKey::new(TEST_IKM, TEST_KEY_INFO)
        .expect("secret key gen from IKM failed");

    assert_eq!(format!("{sk:?}"), "****");

    let key_pair = KeyPair::random(&mut OsRng::default(), TEST_KEY_INFO)
        .expect("random key pair generation failed");

    let key_pair_debug_str = format!("{key_pair:?}");

    assert!(key_pair_debug_str.starts_with("KeyPair { secret_key: ****"));
}
