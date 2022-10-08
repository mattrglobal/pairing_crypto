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
const EXPECTED_SIGNATURE: &str = "a1e27c6142ceb24d9a88ec0f2dfbc22746f3379c99b80c9a4b7c57fe8e673629f9c1d70335a7ed08ca91f50c8959812b38bbb8eb02d0cef7f69e92148a5df0b66cdfd35dc180d9b861ba2675f9e93ad91f1055b707b111daf472a0144d8eb6f36862fcf008ddb93c88752222242d8871";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "88bc863769116546b6078b87025aebcf78ec8083b6b6b78a3a283d4727910b30b303e8943f941c5359262e163fb46f6b0a960e9ff7aa84b137689f7cd2ba8e9ee4fab6046dd8cf18efc91b905832423e099bb67bcff3cc2b44737f039a280728fbb8930b47cd7ab8682c8ed1c9906572",
    "8196c4b417c49664e692474f46896482260e4ad35d823bbf667722e518cc7afb1fd2b2fd513da15af42eaac523711c29477af1ef012fa05febb886cdf530e616e835b05e7ed05631686b5556aac933b7140c4137abfcfd89f40bfed35437e342ca21b93b07a83b76edccade251f9b6d2",
    "972d44483a3c0b6f8654e6fb5157bfa64d2c774891e32db2d7ec441ec32533f07f5227ba5a06aae396e1f51c4f81a8a34268a60ad8fa9f0eb47e6f2b68b457b4d2c188e7b87429e758c8b1a4efa4d0b532d7a435e1cf77e64f058e63bc5e468fbe3342ae48636998aca71bf9d1d9ab1a",
    "8338a122c498a53191f425b11046854e904c35bcd10b75d0ae78396ad829984fd17b2f38387550178ae214bcbb172bf770b5b738a192bbf09c7dad954a7846897eb069d52e80bd75ca2c2be78a43f35e3e44d51ae83d6fc1642729339ddd2ca1deac42998055e4f4c7537deee2d9450c",
    "8818918d518d5c185cfaec56f592d92249105779c169fc7e11db4c492ee3abf441efddd191063eb36b20583b6b24b6be509302ac96736043cef3a55ec7eed0352c2811760da222b515e42064fe904d7e27a9d097f0822c1568afa8055c51765bad226d844929f15c5f4a645f8ed2897d",
    "92d329057b7619860ddb66af04b37a819e41d5c8d4c8ed948b7e902c8f82e6eece557621f1a4449c70eb7d4d7c77c45e1d85e63066ab1c739c536a076bb90777eaed0bea1c50d011a974a89a3f52fc674e0970e5b3ed5a16a9c1d35378173017ea2d11b617da7333d714220e43768a68",
    "ac1963a89878fde126c13a92f6b0a58a5d0a0df349cec5a7cdeb3b6f3b625e2524042faa7c1b4965f76ab94fe5a9e2386d344b53e9399f35bb0d8c48f2250c9930da1dd21597c14181b46efe361271a0435c234e2feb4e496fa46184aaa073ed4b438877d57d36c84841c3dfcc419fb7",
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
