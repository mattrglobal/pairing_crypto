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
const EXPECTED_SIGNATURE: &str = "a14fd5deddd34393ccebae5946a6b0fac1e94c1fa324afc0b68eea2b602fbeee133cfe87be94ee102dca1fd5fc0a874c101a433451a016050f8e109be700b513e742de7770f666397319d7e75673352150c441aace20430fbe308a822e2b3a5882e5a01737ec2c637e8fe29690ae6e34";

// Expected signature for an empty header, TEST_KEY_GEN_IKM, TEST_KEY_INFO and
// TEST_CLAIMS
const EXPECTED_SIGNATURE_NO_HEADER: &str = "9923e48f2144582d0d62034553aee39ff327a1e345500900132956b60a0667cf99777db675b788cdff1822ce1408a128131d89f559fdfdb636fd683e9e97b4938a429bc92dbd3480aa815a5e7fc6a99b27d404efbc236d72430cf5a4f408b1d7cbdf7314aa566708d371cd65125876bf";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
"8a8745e0efe832bea36e35cd9fa60cf93aced4cf6429d6a414a0e4b5ae20f6a46dd6e1e3e8c3b681d41d831b6d78523421d26c306ea82cb571ae883b3328b43dbc864508f214b5e423ffb4a0da9c3dbe2affd962c897033ee7939faa1c2bd104824b6e519071bbe645473660604f2ed4",
"814764df46a6f7085c3ebd6323867287c17a4b53c9281f7765a48cefc16579fa4210fdfe0d7ffa8556af86e5c71f448f504c8f62051ad6054f2deddeb9ac4600302aaf82ceb9bc314c861c4c3af121951a358a951abcda328b14369adc870f3141996299d37a32f3079582a09ee1f531",
"b254a9e013aa1de59f969ab542c578431ac5a370c65e6f2195bdd3168e3e6ff5bfecfdc7287a8a4f58675b184f37931224e45723371c6c8c047e68ca173ee7f6c4bc1fe6993ee55ec9b0303726832c3456281680a23ece89a15bbf04fcf77872b6791b5cf69dbb88b69e57141e1884ae",
"870312b7f874665ee8139a779c62ac8c8875ecc03748b5ca94e8383b5faec6e8daf4df860180523dbfa360a3a437f0dd41b3d6e3baae73d7c577a7fee1535a2f31a00fcff8570ba0b0df1fac664e69c303b1b58b205875acb154de98ad023a1a15039238669204a2cd86b54f0df3c038",
"8436aa432cd7942fee8575261be93412c83ac91fad4a0e3a96327903b4bdc60e739be96a2309f9fa0b484e00401712e2188ea2fb3b84c902fcbf4e62f79beb94f2cdaa8449e18cb1838445a7c311790a6c22aa58cda99dc1ce5e2f773b7fa33da327ead5440e010ce63dfa359f72ba02",
"aa0f3b5913f6562d049299baff70251c018948df48e043aacc22d523179438f13dca3741e65ca7d4201812ab26f151487041a35c47ac85140f5dc4c372e118b783979c019d2c53ee9c607b5e0aedbaf714d1b26997a70578900f84fa2566b6972d9bb9e66207c11c47d138b0a20dccfd",
"b322effd49a97c3fd78aaabd6cafaceb81bda50160a22fd72170b58c28a41c1edec2fbdd46344e03deccf3e6a9dc91e023e4ec6a6e3b5432d2c1bd47b8d8f5c8eb0131eb053f9fefa825f537df6c3c8e584a338054c69da7beddd52f7f013340d993d35a569e6f7edd312eee0d745a6c",
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
