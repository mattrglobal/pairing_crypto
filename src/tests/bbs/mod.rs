use rand_core::OsRng;

use crate::bbs::core::{
    constants::{
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        MAP_MESSAGE_TO_SCALAR_DST,
    },
    generator::Generators,
    key_pair::KeyPair,
    types::Message,
};

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
const EXPECTED_SIGNATURE: &str = "b21f6b7785d6573c74e81fbbd3b7e2d2951aa569ee4d4532021e725056f8f33d78e90d4aa81563fba8b99bf9a8b6aadc3017f7462aada1e908d37e7002d55fe812dd83ba25d338be37f9353a1e0c24d453f652bbc761a40326bd15af5f92b73ca38a56b6ce25aa40e618b4972866c930";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "881624ee88e1bb10787c1d6c7d2bf45a108aed8914c2b5142297d01135edd2e9a18b67d53a565758bce7809e967c94016d04c9ce3256ff347ed656343e81cfb515fc75f88de1fc2c9427765576ad5b243199c0b196d14fb7fb09f51e7af933989f6d8b6bb03bb14e833117776cda8a7f",
    "a380e48ae0b273b9e8ec478fa92090b661611f785d1504c52e6842f61c57be84570cb2593ea410b6b56a685686b3eae435b3d0414bc9a8ebd3544774f444645a59ec98c2f4e8eb9522cdeea639d97bc060f4810f759803a8d6d2e30a4819cf5fe169e5ca453fa65b6119093134db6f8b",
    "b16ed331c572b248afb8546bb6f6a38beef2dc0c58726d1b966a2186da4e92f26673edd86e2c159ed53ec73c502a08f672ebb384d94055ab615daa3c02b003c6449734d39a22b90a648d87295590514a5b841d95570dadad60e138ce669594bdbdbfe078ee6e15958404454c8aa9f17e",
    "af1f1b37290101cb445acd9d49b7ff586a23f1f012cfe54d67ff01e806e1b49db25a25886463387bf2cd9ef98eed93e14b299c0e65d89e91620d478277619043f126f04488867d145da7b61821276a9701c1740b1b05082d823fb0b826bbcd4de0ba540a6bd879d75978a50c7449fd85",
    "b55f1ade8b55b258f1c155bd4d97848a1a85ed5d1f20f6a11e290979daecb81d825a1e8e017f9cf2919348d2e7a0d9466a925de1f242a68f58653c24025d243c82536a7d56dc5884cb5f62937e57a58e2c5b6febe2631153f758e334560cd8acefd801b7929d84737c705f9043b9d4b7",
    "807345840862b1c5ee8b7d087b48a7b811f06d0a1a504c8bf4b1823f730244028c697781ee5ddca60b5de4cc674c62b34e06fb88d4105adc0a37fdb5c2f0e33b8c34e138ef83b6a8774e558cc799f2363cb89c770908de677484000bd779f2c9c4397762ca7c32d798b4188c7ccb5840",
    "a1845b57f423d642747064879a725a74a795af2d82fe8f1f20d7693267162f58579ead1872f2b4572c047a5b7d57ffa057ba8ac7ec22a27301b94b149a5cecb3e70ffa42d3a812da5df00015584cd9bc63004b90620dcad02ff1ddd23ccc520fac4e3b4dab6bcdfcb69843e230d98573",
];

const TEST_PRESENTATION_HEADER_1: &[u8; 26] = b"test_presentation-header-1";
const TEST_PRESENTATION_HEADER_2: &[u8; 26] = b"test_presentation-header-2";

fn create_generators_helper(num_of_messages: usize) -> Generators {
    Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        num_of_messages,
    )
    .expect("generators creation failed")
}

fn get_test_messages() -> Vec<Message> {
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

fn get_random_test_messages(num_messages: usize) -> Vec<Message> {
    vec![Message::random(&mut OsRng); num_messages]
}

fn get_random_test_key_pair() -> KeyPair {
    KeyPair::random(&mut OsRng, TEST_KEY_INFO.as_ref())
        .expect("key pair generation failed")
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
