use crate::{
    bbs::{
        ciphersuites::{
            bls12_381_shake_256::Bls12381Shake256CipherSuiteParameter,
            BbsCipherSuiteParameter,
        },
        core::{generator::Generators, key_pair::KeyPair, types::Message},
    },
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
const EXPECTED_SIGNATURE: &str = "8e1c8c35c7ff8dfe59acdb4c966f165ea929fb45c160b80621c958936b2aca21ad6287b492fcb3d7cfb83b00fd9c97c85f60716b50f128d68c57fc63479cdb761bd603a4fcc6f06cf9481420fe5d5de2317b9fe89f422abe82c8b6dd2fb0a0cad4c7533b1f1a174a3297cbb81583cd4a";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "b8d7b59d586d3ffe2370a872b349057d23b5e86d4b7f6e89129887d9e9a0dc0f6816231962aa7491b6783c080037b97369053b6571812739198446fd2b1cb24e7e39aae5161d88b214eaac85763431b66f1fbd4b96c7f5cf18634b0348e4c0e35ed379b250cbbf17f6e018f81882a45e",
    "8b00154e563a7d74a5f0bd3c2b4cb651aabc68ea1a0eed5ea2614b931231d35c86631b5ad58d450fd30478d2b70df2f45745c019c4aa1973d29506271a16a157a217e37cd6738313b74ffd6bfb3fc2431eb89ae767732a5459eaa0bd08b5e9410cba1970e3838e2fa862963b7cbc7a76",
    "98924872d9253b332c580918a25c2a637e4a0d51e108b9c0c00cc794359f381c489f5567d4009e55d6048812cffc89b753df20b6f83cb5e300c557ba2cc184a7527faed25e9d4d9c8751d34c024bb7f06939df4d185ca942b9fa2d41a60550276cad44d2c8ed9685da451500c3aafa0d",
    "a5a2c00e4406d2c5534348a606f9ed1697ee9b0390faa2792ff2ee40819daaaecb1afa6145f53905e8ecbe800597757e21e1258998d7b0f21222023643080d46328d53653fea2ce74e7a312360e8c8db135d4e6f92a0b86251b9c6877011f6962def69c7a031e3ca070fbead7eb8167b",
    "a0a307e3b2cf6b990e65a2203e6900fbeea67ec6fd1aa87d14c93c39c36c69bd956da30f310c29143876f3b167756c4d10390e92223c00fb14c880bdac8bde6b498d776fdc0fec000ff42d1683fc445d50468ab1f7f849a45bb5a2397f8c6f0d883089691ba402be096294c78626d9d4",
    "880c34047e3256f91c27d8a79aa4420586c547752bbd215d641103cc66cd036864bbd22a28735e43bda0ab463310bedc154f8bbdd3b4b26613387524525b185482a7d0f92366fa08484a26df4def9c251b01ece21d8b141862881748600199a09eb33d5ebdfea9e3cbff9ce846edf555",
    "95835232ce52e6099c196ddbf9f0f57d7d87c718dd790c40955bb2546a3d2760591848f5dc250c720a519d1b9e15bffc70f1586ec50db1fd85c526abc77b0f794a39539b83f6e0d2cac853d0ea80ea47116144529212d2095f85c18d111d4d58bc53546e594f7618d5165ae54b991c20",
];

const TEST_PRESENTATION_HEADER_1: &[u8; 26] = b"test_presentation-header-1";
const TEST_PRESENTATION_HEADER_2: &[u8; 26] = b"test_presentation-header-2";

fn create_generators_helper(num_of_messages: usize) -> Generators {
    Generators::new::<Bls12381Shake256CipherSuiteParameter>(num_of_messages)
        .expect("generators creation failed")
}

fn test_generators_random_q_1(num_of_messages: usize) -> Generators {
    let mut generators = create_generators_helper(num_of_messages);
    generators.Q_1 = G1Projective::random(&mut OsRng);
    generators
}

fn test_generators_random_q_2(num_of_messages: usize) -> Generators {
    let mut generators = create_generators_helper(num_of_messages);
    generators.Q_2 = G1Projective::random(&mut OsRng);
    generators
}

fn test_generators_random_message_generators(
    num_of_messages: usize,
) -> Generators {
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
                Some(Bls12381Shake256CipherSuiteParameter::DEFAULT_MAP_MESSAGE_TO_SCALAR_DST)
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
