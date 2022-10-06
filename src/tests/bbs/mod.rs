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
const EXPECTED_SIGNATURE: &str = "a2aab92b98d680b498b4a677976bc10f6fc340f92c9b51967630d9a1efeb0c82824faa270f4db11cca74ccb8236657d25c9f30bfe9bc8e9d7417e53ee436b94aaa26b18ec4b8fe18e9505663d4990d215a46077ee51baa8e776d7c97c99593fc5130e4c0b7751b324364ef8f14d39434";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "96bfa62541a1b6948d06aafd99138c23e7dfc0a7430bddd293ae9a2fbd49c1e5a271c54e34c699f47dddbcc493915c485f7c7bb68ed9c7bc06beaad407aa91b9dde1857355daf185b2d5e087d0fb966925cbeab0e69dbb58d0583383a1aafbd132129d4bde7521b35f9f459c36dd18aa",
    "a97d308a4541650969937d7f83436776264d658767a03515f4582d8dbb240ce7cf37481cad78588adfc3b801f9b8544373cdc2955b18ce5b72d6961fb7671aa57ddb40ef9bf397aa21b5a4de0dd3a3cd24bf3f9a479960493d0493fa6eaf0d06488d7c858811e4d920ff4c7b5e7dfeb7",
    "a0fe498f0c03982025276f94ea6067a1f462bc7702e59570402de2bc282944f25d3bb3580afdb8124182e1e1c1c1b43a1529099064d6a5169cdedeb03d3493ba41cdfbea998badcb2439076eca203803048760afcdf3c48098f8565070fdc504f2bcb56bb9ee8b1880be6225ebd292f7",
    "8205e68d4777ed538284005bd7540ede01c9b2b73a02ac1664fc9c35710110d0ef3915ab55c806f273ec72432f6376e23d85d0b49dd22e1f63fec5a508f97cc20bbf9aa943d2b0822ab053ac402387be0875705bdd57b95318d26676bad910f445f02e40e9f146b3ddb8c06898a41a3f",
    "8c48184488259cf00e9fdb94210e3fae8c26a2cebeaa4d5223f2dd5a5e4313b2cd88dcc41f08ebb4cb8b835d8bb20ee54b1859b4667674e3821d00a7c40abf4b0837cc39bd3fa7faeccdc866b3bc1e6f38ee44b80aaf66db2b2bd0f1f23d5123f44bc6d4d2fddf6cf797c05165d36f3b",
    "a675e0c1bfdd6777e3b390e082ae6880fb4d9e57b3fc97199e949b4134d969d3d3e703309fade19a25209ba8a5c81dd2664c4035a11f85c291257596616ec600e02a7b76a7a0d5a31d880ad9ac69017f398232378a3488c9c1d9b2a2e3e74bee57237a05c8faf9c84696fecc3f58bd31",
    "a61a017cd32d93dc37bd22778bdd2b56e49ff9cc7b451c45d02385e5322d1c10894f9b6000538faaf192c40988c960ef10e0f9353eb1642097dc08c522efc23886fd3b902bc4b58a8ace9acdeda472cb51d7302f3ea7f1a9eb05b54eea17c501d54cadca633de6a524522b22629947b6",
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
