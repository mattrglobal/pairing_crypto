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
const EXPECTED_SIGNATURE: &str = "8a925a07145e41469f8acd7eed0853bc44f91557c94ed7f55e3e5fc2ee0a2ba65ecfe421c631c424bbe95f5abc6fff8646bfaaeae2bca8636460e0c1f4c1e005ff15872b4d1b8f7e555bf1c39f3306be";

// Expected signature for an empty header, TEST_KEY_GEN_IKM, TEST_KEY_INFO and
// TEST_CLAIMS
const EXPECTED_SIGNATURE_NO_HEADER: &str = "a41a9e4f7660a6745d0b3f8feb930ef66fb0cbe310df6755e4712a634d73f6b7c352349c0159d1af354a53e97689c52735af16881c6e3edd88aafd52f68d4106a905b31d2bf86ed20f900846358f0dad";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "b46f008c4f94f6476049f3c7723c5c806e20ae8ffa5eb2a39b614ac1d6224379db7ef8134d661462fba5568e392bc49c393e2d810f5542c2726328b198f200068636fe181c4fad8b0d356d68b13f58ed",
    "96684adf52b173cd94128f1e813edce620c2a5ab4522a74834cdf69886482c45fd1802514961ee93d6692814bfbce02f7322ff0e8bc125261fdf88cafbeca26c41b91e8442c82ed5471043af825586ba",
    "80e959398370ad309a32f9267c50bf66452627e7e28fac211863c85a09d20a4674eee215cf6535c7366fe124699dc39e661f909ddf0d3f6423fb42b580523cc00882708ef1f61ad7437c643351bab0e0",
    "91929bc91a8fe66767a070e319fe5dc2ee3f09ea3cd65f7b60c78f77eaa689e8630147b2eeb0c534631265f064caed90618cd86061ddcd7432254fa786c733d042131cc36c845f9a2622f22af41e2893",
    "b72d23538f6fe0a5512cb8a647b71fcb2fb50322cf046676955c3cab81ad9a435a5d1d80c64c0e96597957d5a9368d9c5ca42073a13a0401370fca42e0144721f1f5f11512b72826c905c2fa4d1a8273",
    "8ec6f78bb5e67b5567025003bd307599b6bdb64fafbf48e17bcddbedf3e64a40a2ade6e23f93139df760c3adb35e05ec0e9b579034c75d33107d538469e90b4b4dd776f40a866c9dd5adc6b43fcbef9a",
    "914f155019c7735aa6ffde57b45e458ec753427043e16729e250e9162df341d8a3438edad0111268bd76f0c3ad5ca59c29be3a5aa0ab12b1bb9387cc456f8284de5b678f6163b98957282a8435c092f1",
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
    ($type:ty, $expected_error_string:expr) => {
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
            assert_eq!(
                result,
                Err(Error::Conversion {
                    cause: $expected_error_string(v.len()),
                }),
                "`{type_string}::from_vec` should fail - {debug_error_message}"
            );
        }
    };
}
