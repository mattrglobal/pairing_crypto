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
const EXPECTED_SIGNATURE: &str = "8fffe0b47e0e738ff6f8e9ba7c5daa70a3d1a369120e2bf9939a8c442b3b6367a8d77ff932fb5490c954468c3d96617c35d5f394e853bb9dd44ede215a48dd59dc9ca58b19e1d86a8f11ae4def3b1ef5";

// Expected signature for an empty header, TEST_KEY_GEN_IKM, TEST_KEY_INFO and
// TEST_CLAIMS
const EXPECTED_SIGNATURE_NO_HEADER: &str = "8773f52593706c961323c5187c0f2408683b82f3a2a033e6ba4148363a405d3d9c6e7507299b0be0080fda9993e3ae763a80ff914b9364db4ab3309f90e5016ee0ad6d5f34f70f44c5b928aa73c6c63f";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "a1b022a17d9da20fe968adbde9177068b586745ddcab3bfcefdcf887edabd7ed1314cc490a68eacb1f64f8cf1c8d94d428d7444644c42743c5b4415a7efe3c0a60c5a400bf857be43e778732e54f0fc1",
    "9623f8326904b9800d6cc30511b746b1d911c5fcf70e0ad8f2c1ca3171ce684691ffb8a4400eabc941838c12bcbefacc25a95727cb945b040db78b7a221398c75a2ae7c78ba09d1fed508f7db4c8e3f1",
    "802a044807de7dce1c31ba91781588d7c5fa1da1899fbda61494455e48a443695d8fa481172bcd78682b6aaa01fa1e71456ca1df22f3c88032f14b21de83137c93d6b619650877474291bd34b1a5ab03",
    "b3987d33bcef36e1196fd32aa27663c9a69dacf2d7dfb6a0efb1387d8f779b50726095179d5e03c740caa27e5fed692b14d5190af073b43ef4918dc1f00c49739e733290b5e8d45c66ff598fc82cd3ad",
    "8946dba0b24223d74b8e23dd97429dec43c9abee8200e771c4d4c1d98d2d9b51faaeac2fbade639acac219935caf2ff240a1212dbb5ccf120a9726c70ef84f4a4eafca5a29a94593951cd1cc366592e2",
    "b844d0e9922660fea66cb4f74209ff7175459b85289a9f1277ba6a9b666d858abd31b32e3727811ce473f009c6b165f757f0106bda4eca30d225c2e9fb7c5b3bc8e8d70299ee625c037cecc476e82c46",
    "b6a5fb0e42d1b5289402666ee1295e161fd307641280ccfef50d04890e769181b09c065dafe3b9178687f96ce47246733e0f2ef1b6ca610e836d8d2a2aea170f51952e5cd8fa38ad407d12dcbfb63e40",
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
