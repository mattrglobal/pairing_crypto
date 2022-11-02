use crate::{
    bbs::{
        ciphersuites::bls12_381_g1_shake_256::Bls12381Shake256CipherSuiteParameter,
        core::{
            generator::memory_cached_generator::MemoryCachedGenerators,
            key_pair::KeyPair,
            types::Message,
        },
    },
    common::hash_param::h2s::HashToScalarParameter,
    curves::bls12_381::G1Projective,
};
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
const EXPECTED_SIGNATURE: &str = "a3cc68e232545ae2bca1d3c82139473ebdb5be91b22b8b752ed627c5ccbba2f4f8064500262e7eb5daec48aa82fdfb9f359730ac302438858503b46dae4a4f5ef1ce91e01f830dd991ee04b656e4e9e345fe21fd42ecea51d18c6cb6c6569379f26fcb317520303e368cea405ffae7f8";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
"b64ec227bea2a197d5dd230942ec4caa69fcdbc2ae59283e98af6e60b592d1784ebd114381d35d1e64714394f169041867ef2367f4e4991dc262c99bedc7ea41c775d989ad99b8acfa1349c3adf6addd0bd0dc34b4c8819531e7ff97a705d183d585af964ce7a39b6a0edbd79cad1954",
"8d963e689a01047ad115f9117b8d80ed863b50b27080ef3b6d36254246b7dc79c2b4c6648a838cd7874ee7e68100972f5d906380e2404127e8904cbfdf80fff81806aff4ef7eb93b3f261774f5bd735a31e6af6b7a3c30ca142b05320cbad686f8a27ee308ae6440ba935c18087dccb9",
"a66eb1c22a68334d13ebf9c50e1e48c126d6fe3157bf42e3ffd32a481d86ec9c4d64e8841766be634354d027e0ba5d0b1160bd8e177b22a124027f95d6ad342c4d5e50e96f33112cdafd62a626c1917e5e1f863a8f6738cf4180786f76aaea64b00548b5e374660d736b119e3696dae9",
"aa7bc05c5b4f17ad75e6a967a7e13969b739ddd8c935cb77bfb4b693c15296ce3010a82395eb57d9f712bc58170fbcd5507c170a773abfa8319fcb94d2df6d71169b44f8a2804b4353bcc82f05d2d6db255c289463942385c4b7910906cb5a8b61ea610bef081dc5d8830adc3db1f3c7",
"a10e416b1d793fd9f1ad156676272a2927defc6604240c1938b18b1507e27bbbe317a48e0ced0c8c2c2d1180694f05902aed0881a936f7fcea82ba655244cd7e52b5a33e9f50006b383b4c2f15852c143f1f506e019aa8aeeeec2735d39c2cc560e1c55b98254696e58649e298d224e7",
"88d099b4b662e40be9193234f9f0238ac47c761bb91bd5dc9f1903ec1379f56da2cf9a078419da3758f9d40cb466243a3beafb4a8da6b2fe16cc55297fe1ee7981a5f5e0fbc49cec46b91d4f7657c09d38f64472dd119b6e878a87d04ec494f615cbcde7ab564e10e371f99394a8fc2b",
"b8a333fdfaf3ed738e76caf23280bae380c59cf141fd655d8b1efdd11114b1fe09d4ed6ee1570322cc24805d98b0911f5b8b6ec32701a693f41ed2356ec00d8f8a808109f14c08c0a2ed17ee1376a7c5621cf2cee53a64706ecbc7918ebe4815bc2a703f4c9f212fe64af8e275b6588b",
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

fn test_generators_random_q_1(
    num_of_messages: usize,
) -> MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter> {
    let mut generators = create_generators_helper(num_of_messages);
    generators.Q_1 = G1Projective::random(&mut OsRng);
    generators
}

fn test_generators_random_q_2(
    num_of_messages: usize,
) -> MemoryCachedGenerators<Bls12381Shake256CipherSuiteParameter> {
    let mut generators = create_generators_helper(num_of_messages);
    generators.Q_2 = G1Projective::random(&mut OsRng);
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
    KeyPair::random(&mut OsRng, Some(TEST_KEY_INFO))
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
