use group::Group;
use rand_core::OsRng;

use crate::{
    bbs::core::{
        constants::MAP_MESSAGE_TO_SCALAR_DST,
        generator::Generators,
        key_pair::KeyPair,
        types::Message,
    },
    curves::bls12_381::G1Projective,
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
const EXPECTED_SIGNATURE: &str = "a9fad191805006bcf47f88c65ebbdbe599c253afd089a2e0f8674dcdca1ff121c88d325e04dab5d3239480742a03257d279b22f8d80b4c73b1cf90299842e61ca184f58c4fd298ed6b688c8c997e87b711dc992cad720ac8193420c60a9bdc0088cb854a900db6616d65c84e628e9ce5";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "b9bc5ddb6bdbd3b7b60c7e7e57b2dad9c2c0677f94f51e7d9f0df5d446633188058e060b621924cc4393fd63924705815baf10e9234dd953306a295b958902f62052e6a8cf6e6bea9a21781cc37158471504db298ce7e326ce05aa4cb5374c3c74f74f209c8ad7607595c74bc15c9426",
    "89455f50e6ab7cde0684afa49d10f66b8d3545da83a01213b53177ba22d68ca265d4cbb013b003a8598d65b3ca9db7bd0a9d6ecbbffd7ff916fc950e768d85b5efd19c03ac4cb93c95119aa40f8048cf0d30e89180c0617a7d31c0d17e3f85d84eab681b8593448321dd191ef4f45183",
    "b505410652af38a74727227e530a5753ef890d017b86937629c85543e2c1b2c955d5fa1ab1cfd68925041809cd9bf1251d3b6c75a041ae626d740ce576c0668d9487ddab1733eae33e078b10e17535ef490b5ddc5a9b9325f267889c8c2537437f21529c915ecfda11d9d533c88d1ece",
    "8226da54c3d92213cf2a8edfdd7defee7db9d2dbc9158bfd05e14743ad2b93bd0e121758cc1c4e084b1abfbf3f6715da13a5cd1f9ce2a9de80e6b7a6832a6d9d33dd58433c5a9c3e7c24301c4c6cc53e180d11749661b4eefaeead391c5c55833ea751c40c4138cd2ee3a742594f489c",
    "8bda3c7608760bbc4c338c83502668491ede90e9e700f7eddb2720333ba0f220ee48ace2b2356413ba12fd0bac6805ef4ddd2d334176bc02989c0a2f11e630697ef58039b57f5bb4276fc2e14e59e4d6599238729b642a9af5f1e2f59102b30b41cb3fe822e0a7276541f851c5ed398a",
    "a741b26906b6646624b7a6c26f1e2c53a8e18b2d2dd7affe0b8ec1792db8535dc8811f718215a4a08368d25d7e6801a61e997921d4c99cb8dcbbb9a6b0a88b8913779526c8a19d1eaa1efcb390c2cdd907793f148127d175d302e251a5e9beaddc11b5f38578774ee3539e197d2ef67d",
    "8704ecdbd7dee870916a071c694b71b910d1c8bafd446fa5d91e34e58913a1f100d248644f5c4560deb79f9d9f018e271e3863673b52ed37d3f76e898c1e75f2a2f9f0c297c85ce40c56a7a05f8005d313b4b16a59c33fcd583a12f4e7eac94553b6a459e7229b964dbb06e41e585638",
];

const TEST_PRESENTATION_HEADER_1: &[u8; 26] = b"test_presentation-header-1";
const TEST_PRESENTATION_HEADER_2: &[u8; 26] = b"test_presentation-header-2";

fn create_generators_helper(num_of_messages: usize) -> Generators {
    Generators::new(num_of_messages).expect("generators creation failed")
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
