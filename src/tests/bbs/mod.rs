use crate::{
    bbs::{
        ciphersuites::{
            bls12_381_shake_256::Bls12381Shake256CipherSuiteParameter,
            BbsCiphersuiteParameters,
        },
        core::{
            generator::memory_cached_generator::MemoryCachedGenerators,
            key_pair::KeyPair,
            types::Message,
        },
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
const EXPECTED_SIGNATURE: &str = "ad644efdb0c054026042342c10ae3b52e80050b76da49f15c6a0308dd357aa2331e5e2247b0e68dc2f52a912204905a65c9f30bfe9bc8e9d7417e53ee436b94aaa26b18ec4b8fe18e9505663d4990d215a46077ee51baa8e776d7c97c99593fc5130e4c0b7751b324364ef8f14d39434";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "b6686e89636673c3f52d67dd39f0b39fbc7b82b4e7897bda124329a8e47efe27c984c775907c89cb34424b6a56dec2885f7c7bb68ed9c7bc06beaad407aa91b9dde1857355daf185b2d5e087d0fb966925cbeab0e69dbb58d0583383a1aafbd132129d4bde7521b35f9f459c36dd18aa",
    "b63fd2b7b7d092af3f1b1656d60a4415c3990f9de122a023a71ca941d72ac88c734f8804f5ef23e3a0f25d77e5e0669073cdc2955b18ce5b72d6961fb7671aa57ddb40ef9bf397aa21b5a4de0dd3a3cd24bf3f9a479960493d0493fa6eaf0d06488d7c858811e4d920ff4c7b5e7dfeb7",
    "a310d46e9ecad20c5cff4050cbe8066c93cf33496839b27eb1b8cbb91b4aac9b3e6cf6c3710097b4dfcc8208c2e775f21529099064d6a5169cdedeb03d3493ba41cdfbea998badcb2439076eca203803048760afcdf3c48098f8565070fdc504f2bcb56bb9ee8b1880be6225ebd292f7",
    "967b60f0f42f3017872521dbc133a99d530c8db274ad9bcfb6153a7fcb5e5b587d894cca9af3b1154fbc9d62ff09b2d33d85d0b49dd22e1f63fec5a508f97cc20bbf9aa943d2b0822ab053ac402387be0875705bdd57b95318d26676bad910f445f02e40e9f146b3ddb8c06898a41a3f",
    "a88f1503840d4a22d142b182083a4cb1ab54d40e8ceb9410958cf0804089aeb8f335728f635aa17a3ccb4d70d8bfe4774b1859b4667674e3821d00a7c40abf4b0837cc39bd3fa7faeccdc866b3bc1e6f38ee44b80aaf66db2b2bd0f1f23d5123f44bc6d4d2fddf6cf797c05165d36f3b",
    "983bcc97b3d37e2718a344f8c140b3bf7d744cb2de20c2a8b372f0f5e6e8ac0fcc5ad4fe3057e50c0525117d2a8fefba664c4035a11f85c291257596616ec600e02a7b76a7a0d5a31d880ad9ac69017f398232378a3488c9c1d9b2a2e3e74bee57237a05c8faf9c84696fecc3f58bd31",
    "a27cd6d07201615c8ea146d8237d5d193a3a4e9fb0cb8ce48f418a49f617da3db73a85bf86c29b3950dacd7566161cfd10e0f9353eb1642097dc08c522efc23886fd3b902bc4b58a8ace9acdeda472cb51d7302f3ea7f1a9eb05b54eea17c501d54cadca633de6a524522b22629947b6",
];

const TEST_PRESENTATION_HEADER_1: &[u8; 26] = b"test_presentation-header-1";
const TEST_PRESENTATION_HEADER_2: &[u8; 26] = b"test_presentation-header-2";

fn create_generators_helper(num_of_messages: usize) -> MemoryCachedGenerators {
    MemoryCachedGenerators::new::<Bls12381Shake256CipherSuiteParameter>(
        num_of_messages,
    )
    .expect("generators creation failed")
}

fn test_generators_random_q_1(
    num_of_messages: usize,
) -> MemoryCachedGenerators {
    let mut generators = create_generators_helper(num_of_messages);
    generators.Q_1 = G1Projective::random(&mut OsRng);
    generators
}

fn test_generators_random_q_2(
    num_of_messages: usize,
) -> MemoryCachedGenerators {
    let mut generators = create_generators_helper(num_of_messages);
    generators.Q_2 = G1Projective::random(&mut OsRng);
    generators
}

fn test_generators_random_message_generators(
    num_of_messages: usize,
) -> MemoryCachedGenerators {
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
