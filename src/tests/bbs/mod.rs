use crate::{
    bbs::{
        ciphersuites::bls12_381_g1_shake_256::Bls12381Shake256CipherSuiteParameter,
        core::{
            generator::memory_cached_generator::MemoryCachedGenerators,
            key_pair::KeyPair,
            signature::Signature,
            types::Message,
        },
    },
    common::hash_param::h2s::HashToScalarParameter,
    curves::bls12_381::G1Projective,
};
use core::convert::TryFrom;
use group::Group;
use rand_core::OsRng;

mod test_data;

mod generators;
mod key_pair;
mod proof;
mod signature;

const TEST_KEY_GEN_IKM: &[u8; 32] = b"not_A_random_seed_at_Allllllllll";

const TEST_KEY_INFO: &[u8; 52] =
    b"this-IS-some-key-metadata-to-be-used-in-test-key-gen";

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

const TEST_HEADER: &[u8; 16] = b"some_app_context";
const ANOTHER_TEST_HEADER: &[u8; 23] = b"some_other_test_context";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFO, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURE: &str = "ab52e7130369a510afb34ddc2ef2b5e8331a3dcdd5a25685aa5ee5c1ad2e732d24668db0cd41f21c2a122d882f792f915744922c39534fb2c09b45d445ead88c631006eef6ab39b2e5b4c37542af2e7e";

// Expected signature for an empty header, TEST_KEY_GEN_IKM, TEST_KEY_INFO and
// TEST_CLAIMS
const EXPECTED_SIGNATURE_NO_HEADER: &str = "b68dd6571cabcbbe871aa299b391ef966b8256e1ba5b3283d5c1cf3b3dd26bb78f9672b7b97ea9cc1e68a29780235a4924be8b0843382d27f8a434b5d7a11831a0ddbbfcd2b6b7ba1909853ae9d66c22";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "89621b2e1d74cb506407a87ee882d783aa494ca6a709c1390be21a465c5e36a9381a9ca0672c06c68a47827183eca3545bc913e2bb25c87a2e77980c2f696e1224aa4f432c5fadce4f2b1f8f66369d73",
    "b936e45bf26e945d9aa47c3dd7a79070346d24380e8f8ea2bf5e4dba54f01a9250ab2216ea4cca8133c097fc9acb3a216ddb6b8ea99f54708a0445d158e6b88e6dec34bb7adda23b6c9ba054fba5b03c",
    "9613bf535eba8dc56e594e1a32626a1b3fc2792b3f6be3465cca7942cc55b6ad303498e0c11756f708d95dde6419c8fc4938a2fe43e972b7b02eb642dd7307096e7b0785fa5e12e7b8f5d2842955b604",
    "abd5f9346ae4ffc926512377d7b05b1248d365f17dfe473f440470808d05e686080fbfe730de7ef7c95601f1021b879a572e1fcf10d1dda9949866494f9c2b529985b26826a6a389cc870136a4d0fe33",
    "80db52e1ac3cbff90596a38845ec6a3d052fc5c0cddf4d6fa77580bb2c73d8be2782abc17a2d4324a5ba5241fd6e70474ac5672b5c01ffdc9a69a3ca7e78cf01e58541e2e08ed4d95fc073bb4c1fa6fe",
    "8b69d79459f3eeead5a2fc8793c6dc01186c45af57876c960caa01f93fd331983daa0b459bbeae170de7476b83da1bd03a5e8b215845f5dbc1e10d75903c2eaff52ec66307b356c987efa456b5f21e2d",
    "a933b9c6d80eaf9082ff1b2c14b958f7cdd6f73ea59c76fcfdc12f53786123ed5405091b0cf93593caa4b8a970c804ba70d2ce339f7c0c53422220d6a5f7e8d7e669023df38c2a6c92b0821acde131e5"
];

const TEST_PRESENTATION_HEADER_1: &[u8; 26] = b"test_presentation-header-1";
const TEST_PRESENTATION_HEADER_2: &[u8; 26] = b"test_presentation-header-2";

fn create_generators_helper(
    num_of_messages: usize,
) -> MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter> {
    MemoryCachedGenerators::<Bls12381Shake256CipherSuiteParameter>::new(
        num_of_messages,
        None,
    )
    .expect("generators creation failed")
}

fn test_generators_random_q(
    num_of_messages: usize,
) -> MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter> {
    let mut generators = create_generators_helper(num_of_messages);
    generators.Q = G1Projective::random(&mut OsRng);
    generators
}

fn test_generators_random_message_generators(
    num_of_messages: usize,
) -> MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter> {
    let mut generators = create_generators_helper(num_of_messages);
    generators.H_list = vec![G1Projective::random(&mut OsRng); num_of_messages];
    generators
}

fn get_test_messages() -> Vec<Message> {
    TEST_CLAIMS
        .iter()
        .map(|b| {
            Message::from_arbitrary_data::<
                Bls12381Shake256CipherSuiteParameter,
            >(
                b.as_ref(),
                Some(&Bls12381Shake256CipherSuiteParameter::default_map_message_to_scalar_as_hash_dst())
            )
        })
        .collect::<Result<Vec<Message>, _>>()
        .expect("claims to `Message` conversion failed")
}

fn get_random_test_messages(num_messages: usize) -> Vec<Message> {
    vec![Message::random(&mut OsRng); num_messages]
}

fn get_random_test_key_pair() -> KeyPair {
    KeyPair::random(&mut OsRng, TEST_KEY_INFO)
        .expect("key pair generation failed")
}

fn get_expected_signature(expected_signature: &str) -> Signature {
    Signature::from_octets(
        &<[u8; Signature::SIZE_BYTES]>::try_from(
            hex::decode(expected_signature).expect("hex decoding failed"),
        )
        .expect("data conversion failed"),
    )
    .expect("signature deserialization failed")
}

#[macro_export]
macro_rules! from_vec_deserialization_invalid_vec_size {
    ($type:ty) => {
        // For debug message
        let type_string = stringify!($type);
        let type_size = <$type>::SIZE_BYTES;

        let test_data = [
            (vec![], "empty input data"),
            (vec![0; type_size - 1], "input data size is lesser than 1"),
            (vec![0; type_size + 1], "input data size is greater than 1"),
        ];
        for (v, debug_error_message) in test_data {
            let result = <$type>::from_vec(&v);
            let expected_error_string = format!(
                "source vector size {}, expected destination byte array size \
                 {type_size}",
                v.len()
            );
            assert_eq!(
                result,
                Err(Error::Conversion {
                    cause: expected_error_string,
                }),
                "`{type_string}::from_vec` should fail - {debug_error_message}"
            );
        }
    };
}
