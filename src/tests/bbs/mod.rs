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
const EXPECTED_SIGNATURE: &str = "ab32977ca295eeaed27c0c936b3fc60cc55e7cab8219c1017dc498589b487c9f3bff4f063051d69fa157764012686e5b138adde76d2943bfb66ea0e723387b2c526f11bf91cb801baac49f7bbb744a5e";

// Expected signature for an empty header, TEST_KEY_GEN_IKM, TEST_KEY_INFO and
// TEST_CLAIMS
const EXPECTED_SIGNATURE_NO_HEADER: &str = "85d9d04313749c5f4de8a29f89408168b001c342937b88b2b1302b5e8a80ac654b52a980894b8ae22f605af835d72f1e3ed2a5686665de0a66c1414b6e9742ac3395f46a03fcc1c19732a03f5cbfb603";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "925b257838bbc46d0927538e1609867dd563550e9daade709ba0b1b4642df2a1da46c481de8c44184163bd164cade2c75911e31df92a04b8a825b10275109af76f6d28fed3e8c40a7d601edf870d7899",
    "a6324bccce90bd0871d5a8f56bc32ab54fec4f58a7f36cad92d2fd8d9291b0ab621f9a636fbc835b1aa2fdb6ad7c9cc25d01fdec7e0307d844cf9d70daf0a2a326eec716660a96536bf44b6036a6204e",
    "b58586b4ce4114cbe5b2de5bc49d85d4488744ba6968e95db902c7b4489a42b0217dc3b6eabb4846f1a7382bada4778f6f18f64ddf617916a41a84ef855061a6d730b0a3effff64c3cd05ceb166c6a4e",
    "b97bca812bfe7e953fb59c3fe02cf9045d6c0e5c5ae411b83934a0f512fed68695db5bc5df8f48ef87cb13179fcca2ce239dee06d49fee691ef1aeba52992a02ed506ec0fcb404a3096d1a143e1df0b4",
    "804317f0ff0ede4a80125973f6a6d43fdb8a90f3f1544c64be977ac2ba7ab11881198a9d281efca1ca6c7b3ec279873f6c27a34d4a9ddc35ba4d71274a6050948bfab65d967fca4f5406774a045b4088",
    "af9a76d7cc2ccd9687ff7bcfd49e5147a81cab7b66ca62f6ac294af3dfab30eab610f98b1b3e62932940797ba520ce9c51517f7c75fc928a0a2c3be28b292a2f110c6baf80b025793669caa31667fac4",
    "8df37099068494eaeadae4fd782cf4aa9cc3edc4481f984ee191c9f22e42670d1235f823e8dd84f13d06e88bc8290df24315e390ec9b13d686f149d798c67622083a3ef2c3aab4c84783a7fee591e47e",
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
