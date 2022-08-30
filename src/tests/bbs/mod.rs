use crate::{
    bbs::{
        ciphersuites::{
            bls12_381_shake_256::Bls12381Shake256CipherSuiteParameter,
            BbsCiphersuiteParameters,
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
const EXPECTED_SIGNATURE: &str = "8354e0255522f3a024620e697624f7386cfb55d16ed277367f4650e64a433d411688041126190dbeb6dc31a0ab8da81838bbb8eb02d0cef7f69e92148a5df0b66cdfd35dc180d9b861ba2675f9e93ad91f1055b707b111daf472a0144d8eb6f36862fcf008ddb93c88752222242d8871";

// Expected signature for TEST_KEY_GEN_IKM, TEST_KEY_INFOS, TEST_HEADER and
// TEST_CLAIMS
const EXPECTED_SIGNATURES: [&str; 7] = [
    "b9a53813dd344dd8baf51695f7af2aef330b2c2fcb40c5ea213e91d5ea3efb41128cc9613a87a8c07e17d38091f3d9ba0a960e9ff7aa84b137689f7cd2ba8e9ee4fab6046dd8cf18efc91b905832423e099bb67bcff3cc2b44737f039a280728fbb8930b47cd7ab8682c8ed1c9906572",
    "9592ee0d1d4a977b4dc93815fe0bb9275b19b66f1685a6f4eefb527229cbd45cfdcd00504a09bf7d49a6d60e503d978c477af1ef012fa05febb886cdf530e616e835b05e7ed05631686b5556aac933b7140c4137abfcfd89f40bfed35437e342ca21b93b07a83b76edccade251f9b6d2",
    "9413ea234382535188323d0fef35c500eb534ed66ca42171636ef31ba67bdc9890599e7a54686f9a41ab8c0cb2fec5c64268a60ad8fa9f0eb47e6f2b68b457b4d2c188e7b87429e758c8b1a4efa4d0b532d7a435e1cf77e64f058e63bc5e468fbe3342ae48636998aca71bf9d1d9ab1a",
    "ac7a8b3c0e4d03fe63752e460063e98b6228b430e6faa0194c58ed578a4c492a78b69a37624d35e661bacee4a6c7657b70b5b738a192bbf09c7dad954a7846897eb069d52e80bd75ca2c2be78a43f35e3e44d51ae83d6fc1642729339ddd2ca1deac42998055e4f4c7537deee2d9450c",
    "875221d857a0231bf9257f8f82306fc2c87dd02609a54a84f795c13cac00d24dbf748bc2efce3c8dfdd4c0b0b84eb1d2509302ac96736043cef3a55ec7eed0352c2811760da222b515e42064fe904d7e27a9d097f0822c1568afa8055c51765bad226d844929f15c5f4a645f8ed2897d",
    "86fd52f3c41584a2847bf9d0a4c8e475f09ee190c1a9e7e95152dcfdd66d3376ff08bbfaf7336c3eb6367dff088b11461d85e63066ab1c739c536a076bb90777eaed0bea1c50d011a974a89a3f52fc674e0970e5b3ed5a16a9c1d35378173017ea2d11b617da7333d714220e43768a68",
    "845463d7addd3e3967411b26eb6afee4e9c3707b7ee9348c7bae205cf096cbb5589f90f6b79abe40127896c5d27ac4056d344b53e9399f35bb0d8c48f2250c9930da1dd21597c14181b46efe361271a0435c234e2feb4e496fa46184aaa073ed4b438877d57d36c84841c3dfcc419fb7",
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
