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
const EXPECTED_SIGNATURE: &str = "9807eefe48bbb6243f7966b0ac926d2299bdc3d7d3f8f72abb532ea92547e26a783aa8f57455b8612d5bb626895b8597575e90edefeeb44ccd046fa1105140b7bfd2ee5e0b2449f078a2d743de34ad30";

// Expected signature for an empty header, TEST_KEY_GEN_IKM, TEST_KEY_INFO and
// TEST_CLAIMS
const EXPECTED_SIGNATURE_NO_HEADER: &str = "937647aea4a671d582898726520cc289268d1147a6da0adb9a874fc6e9904f570ffcd979985232bb9344e14ea9663f8f49cb8408e9156ae4b0e4dc53dc5806d14248de0e0897077c6713bdaff1d2b827";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "a3af298f47792f6268bfcc957fd2a5ab859ed5e21bbe9142c9ed58d428412c6f2342f39accfc031a879bb58b73d908243ea7102faff9f93b34b322e2707d74d61b6a90fc04e687860796f087ac0f6f37",
    "859d43ff7820029f04a0852f97bce28c7fd90804cafcd773114cc33035e6b229d60e7831fd8b92a4c7cfa556449fcf32500343e9314672aa736650b614f5344e41c98d6b114132fbc9ec9cf881e2b635",
    "8b1c3b4426d4d9faba58649852f51c229c26d1ed92475e0588febd3e94d33f5df03cd9222b8977948ee0b76c03920e114551ebb6f0e5663c01371ab5c715a0e4fd2140edbe9c1ae0729be7c29c1d2608",
    "864534d1f13ea279b9013c91ac3c7bf5aceb652edd537604c56750233ef907d1a6ec796c9f5fde0997bc45334eb725003c144ca0990ab8229bc62d1d80c5016c5abc52fb34bc5d831d502c553504e926",
    "b626d87f74da74c5eb745e8891625d22a7e76217795430471b6711916f504a901df2bb4ae58933cb5e434175f52dfb43430e3a22e989dbc1dd5ac837529f16c520fa1d892a6f9e515ec0924d5d6e1589",
    "8fd3f81c861ebf586d6f38acb1324bb900844da0d5a6fd051ca7a280156431f3d614aaa6bb2cf25f8119d7b3b0dbcb6502f6b9ed48e4feeb4bb2782aca14f8c8fed2bafafb3057a1901cb4f3f9375ce5",
    "a42ba5172b633683d9cdffd9f0b5d6d8140ee64a9afa1d286260cacb5d95b62c458f99509729c4b1f955ef147e16dcfb6881e5aa8126bb4d6d6867f0619a8a466797a964ce100bcdaa0dc1f911d79b59",
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
