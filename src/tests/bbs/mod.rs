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
const EXPECTED_SIGNATURE: &str = "a461e5c600d27f0cbcaead2c428e78eae5b86a23cd24673cf3674928f3817fecf67fea1ff0c52f61fbd4c530524353b313d5e180dc5d75a3de675ccdfb8d63d2ee700911d7e80e269a2c0af1da389a686e107ef6c3feba1cf4b9e293968af955e12b93bd2c432af48293f93442a012be";

// Expected signature for an empty header, TEST_KEY_GEN_IKM, TEST_KEY_INFO and
// TEST_CLAIMS
const EXPECTED_SIGNATURE_NO_HEADER: &str = "add621c7166a3a16beb738afaba0183d2a99e52a662d845a97e23d6f1f1624b8708dee04ce463266afbd881e58207a5817aa308b4526358fa6215cfa7dc33e5b23ab95d272a894f086a1f15eb0f9292f29b7d88633bf00c5734e8a3040848e2c29cfeb0b2d3784debd60e4eb067759d5";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "a533763a64308d07aa3f38b0dcf34fabc7b2414bbfb4845beeb66fd2d110c5294615d0c3c3f32ec373bd808aa974e5582fd28c0e6ae8564350fac963a22a428c1f3cfe13fb0f52f1cd4392f93218144047597f124e77cf7d69a565ccf9233fd9db52a9490b2628ac6b5db9b4268c66dd",
    "88b286f51f8f3e7a7242c18efd7eb7535df8dbd0967377f6074860eb0b6868dafa4e35958fec7892e611464f0aba89960caa0a6accc22d69474ec3209b2b84f13d91bdcba65adb1206f21d68e293453917dc3cffa1699d64ba9ef5f493ae44feb304f5cd6f503aa74668af2c5713304d",
    "b35a6e23074344ed03499c61e3ac8dc198a62d613769bf0e9b4068fa4195b6a5708983dbc72da4f118e0f0c641b5eeb00518e79d3db333a258a72c855fed1e42b2896a06a0e2c6fa10a760ee986d62be40ae3b686ec6c2388743e3f053cbd9c8be97af4843e8f068901a484712e2264b",
    "966f9a3cd457499ab31e3abf5e81611698f867f625f880b38060f8d7d6ef99622ba5c567011683e52d1b628fe8c6f5d7319bacdba0976cbd993264b57a50085f7ba980cd57e72a272f0a4ea162f1b8330ce704b2946be5ddd27bff9f875f573d1aec3ebabb976dc1d656f5e8cf3fa324",
    "b7a02d7e878dee2b279d4aceccd22bfce93db97f6f095b2b3db9bdbf4e0da3deb5eab38832298aa54d7f8bfe40dd89be648e9219ac972a82827d525a952ec5cb7c85d5e495cd9533c47ffb2a490e92f2530c0b8116c390586bc990b42ed0e267a319e84a8ffd16b57cff38905db85183",
    "b560935fe26ffcb1246279b1d6031c0cf22effb77b19c04c2f295a30bd2644a71386e55ea148a63917e2fec9be92515d5637254905ec20301c986cb50623f7ed7472d76ee9287ad7886e112c750a19c64592a7be92f83974cd7abd0735080dafc41c343983f3ca5dedf5bbc2bbd09c76",
    "9738903809afd7ddba28368582935fe6f889207419564300cc568dc8b6b21db34070e96e72863247b1825a75270d7c6673953070e34f0aa1ff313a0a0c645c84e075641f476a4ba238a3dae8d41e87881e352246e4a07baf871a6f85fe19e9017f72c92e134f263cee3acc93086b558d",
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
