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
const EXPECTED_SIGNATURE: &str = "8802d788c8b7e854abdf4ad64f5794b84c3ebd9ae85b45044705f31e2f9590c6788a94f7c6c7e057f15b06b5eb9febeb5a00d2882f98db5704d652408b0d7b13a1dbff8d08451c086bf3bb8714849f3d";

// Expected signature for an empty header, TEST_KEY_GEN_IKM, TEST_KEY_INFO and
// TEST_CLAIMS
const EXPECTED_SIGNATURE_NO_HEADER: &str = "b32652b7fd05ccd1f013857dc7ec56f035af513fd4c8b813a8662c13ee8df93c1265e917487d736f13768f7ce31311893f43250a97666cd36b9e3abcd3c7e358664a857c74c9bf6b0499adbdd2754e5b";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "9393543a9bca66a2691894447923d0b45b9868f514ad7b7ccf62fd5c6798cb4c17b6135e44c337fe24bd083151ce5e5150de86a1c81364043a8e099a8226010bdad2708c521f8dc002f1db74d32bc5bb",
    "97725983a655c7737fbeb3117074c596a44c9240111d8a593530601c1bd1e81302eacbe4798d1e2d75109d358c87e42631db6554a80fd85211dd6031f1b29ffe5f2a0e78ff2958aad2311faa31a72363",
    "adbe9f251c5093c2f45811a4868ee07dcb6d862b9cf518557afb51d5610049c4b8a3514eb31d6c5aaa5754cd41c73ed06b69a24f93f47fa07591d25d0b465cc90742a3dc6407eea0c5b5c2bd7964f443",
    "b758a9c4396abbc4ad086858b573d14d1ab2a9e048afe395c3f6b34237d5303110343a273366b190b0721acd731d6ef41da5852a829a5b8ac9102800bc6427070ede62400132312b5dea012f798a727c",
    "8e1e0a1ddc6fbaccca8c121879cfe2c4a87b63e68ae3796509be311d8bbcd77ebfe427088f13d30adbd3786585ec28b707292fe55a1028f9ea2939dda071437abb9aa7541e8c0b81a8d53061d55b9ef6",
    "89e02e0bb93ae723b60b0c917024c5b6e8a539148e561dca43de1f26e5e41362ab2fe63ba1cbb8cbe036559d511944ce44df3534ba61e10a24d92cec683b5d958589c7317a320ea9aed97a5f6fb16850",
    "9865b388431254c414fba8113336d7fabbba98a777e0171624ff92cbe899142b5d95d5dff69d68727669af33158dbc8047ff6583f7f3424f406f20d617744736afb42774077215497812ab658a92bc0f",
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
