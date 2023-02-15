use blstrs::hash_to_curve::{
    ExpandMessage,
    ExpandMessageState,
    InitExpandMessage,
};
use rand::{CryptoRng, RngCore};

// A Mocked Rng based on expand message as defined in
// [https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-expand_message]
// for the purpose of testing only.
pub struct MockRng<'a, E: InitExpandMessage<'a>> {
    v: E::Expander,
}

impl<'a, E> MockRng<'a, E>
where
    E: ExpandMessage,
{
    /// init a mocked rng.
    /// - seed: The seed from which to create the random numbers
    /// - dst: The dst for expand_message
    /// - count: The maximum number of random elements
    /// - expand_len: The length of each random element
    ///
    /// Note: count * expand_len is the maximum number of random bytes
    ///       the RNG can return.
    pub fn new<T>(
        seed: T,
        dst: &'a [u8],
        count: usize,
        expand_len: Option<usize>,
    ) -> Self
    where
        T: AsRef<[u8]>,
    {
        let dst = dst.as_ref();
        let seed = seed.as_ref();
        let expand_len = expand_len.unwrap_or(1 as usize);
        let expand_len = count * expand_len;
        let init_v = E::init_expand(seed, dst, expand_len);
        MockRng { v: init_v }
    }

    pub fn fill(&mut self, dest: &mut [u8]) -> usize {
        self.v.read_into(dest)
    }
}

impl<E> CryptoRng for MockRng<'_, E> where E: ExpandMessage {}

impl<E> RngCore for MockRng<'_, E>
where
    E: ExpandMessage,
{
    fn next_u64(&mut self) -> u64 {
        let mut buff = [0u8; 8];
        self.fill(&mut buff);
        u64::from_be_bytes(buff)
    }

    fn next_u32(&mut self) -> u32 {
        let mut buff = [0u8; 4];
        self.fill(&mut buff);
        u32::from_be_bytes(buff)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("failed to fill destination with random bytes");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        if dest.len() > self.v.remain() {
            return Err(rand::Error::new(format!(
                "{} random byes are remaining, but {} where requested",
                self.v.remain(),
                dest.len()
            )));
        }
        let len = self.fill(dest);
        if len < dest.len() {
            return Err(rand::Error::new(format!(
                "failed to generate {} random bytes",
                dest.len()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blstrs::{
        hash_to_curve::{ExpandMsgXmd, ExpandMsgXof},
        Scalar,
    };
    use pairing_crypto::bbs::ciphersuites::{
        bls12_381_g1_sha_256::ciphersuite_id as sha_256_ciphersuite_id,
        bls12_381_g1_shake_256::ciphersuite_id as shake_256_ciphersuite_id,
    };
    use sha2::Sha256;
    use sha3::Shake256;

    // Expand message test vectors from the latest hash-to-curve draft:
    // [https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/]
    const INPUT_MSGS: [&str; 5] = [
        "",
        "abc",
        "abcdef0123456789",
        "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ];

    // output len = 32
    const EXPECTED_SHA256_UNIFORM_BYTES: [&str; 5] = [
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
        "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
        "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
        "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9",
        "4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c",
    ];

    // output len = 128
    const EXPECTED_SHA256_UNIFORM_BYTES_LONG: [&str; 5] = [
        "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
        "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
        "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df",
        "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a",
        "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487"
    ];

    // output len = 32
    const EXPECTED_SHAKE256_UNIFORM_BYTES: [&str; 5] = [
        "2ffc05c48ed32b95d72e807f6eab9f7530dd1c2f013914c8fed38c5ccc15ad76",
        "b39e493867e2767216792abce1f2676c197c0692aed061560ead251821808e07",
        "245389cf44a13f0e70af8665fe5337ec2dcd138890bb7901c4ad9cfceb054b65",
        "719b3911821e6428a5ed9b8e600f2866bcf23c8f0515e52d6c6c019a03f16f0e",
        "9181ead5220b1963f1b5951f35547a5ea86a820562287d6ca4723633d17ccbbc",
    ];

    // output len = 128
    const EXPECTED_SHAKE256_UNIFORM_BYTES_LONG: [&str; 5] = [
        "7a1361d2d7d82d79e035b8880c5a3c86c5afa719478c007d96e6c88737a3f631dd74a2c88df79a4cb5e5d9f7504957c70d669ec6bfedc31e01e2bacc4ff3fdf9b6a00b17cc18d9d72ace7d6b81c2e481b4f73f34f9a7505dccbe8f5485f3d20c5409b0310093d5d6492dea4e18aa6979c23c8ea5de01582e9689612afbb353df",
        "a54303e6b172909783353ab05ef08dd435a558c3197db0c132134649708e0b9b4e34fb99b92a9e9e28fc1f1d8860d85897a8e021e6382f3eea10577f968ff6df6c45fe624ce65ca25932f679a42a404bc3681efe03fcd45ef73bb3a8f79ba784f80f55ea8a3c367408f30381299617f50c8cf8fbb21d0f1e1d70b0131a7b6fbe",
        "e42e4d9538a189316e3154b821c1bafb390f78b2f010ea404e6ac063deb8c0852fcd412e098e231e43427bd2be1330bb47b4039ad57b30ae1fc94e34993b162ff4d695e42d59d9777ea18d3848d9d336c25d2acb93adcad009bcfb9cde12286df267ada283063de0bb1505565b2eb6c90e31c48798ecdc71a71756a9110ff373",
        "4ac054dda0a38a65d0ecf7afd3c2812300027c8789655e47aecf1ecc1a2426b17444c7482c99e5907afd9c25b991990490bb9c686f43e79b4471a23a703d4b02f23c669737a886a7ec28bddb92c3a98de63ebf878aa363a501a60055c048bea11840c4717beae7eee28c3cfa42857b3d130188571943a7bd747de831bd6444e0",
        "09afc76d51c2cccbc129c2315df66c2be7295a231203b8ab2dd7f95c2772c68e500bc72e20c602abc9964663b7a03a389be128c56971ce81001a0b875e7fd17822db9d69792ddf6a23a151bf470079c518279aef3e75611f8f828994a9988f4a8a256ddb8bae161e658d5a2a09bcfe839c6396dc06ee5c8ff3c22d3b1f9deb7e"
    ];

    macro_rules! test_mock_rng {
        ($expander:ty,
         $dst:ident,
         $count:literal,
         $expected_bytes:ident) => {
            let count: usize = $count as usize;
            for (i, msg) in INPUT_MSGS.iter().enumerate() {
                let mut buff = vec![0u8; count];

                // test fill bytes
                let mut mocked_rng = MockRng::<'_, $expander>::new(
                    msg.as_bytes(),
                    $dst,
                    count,
                    None,
                );
                mocked_rng.fill_bytes(&mut buff);
                assert_eq!(hex::encode(&buff), $expected_bytes[i]);

                // test next_32
                let mut mocked_rng_next32 = MockRng::<'_, $expander>::new(
                    msg.as_bytes(),
                    $dst,
                    count,
                    None,
                );

                let end_idx = count / 4;
                for i in 0..end_idx {
                    let dest = mocked_rng_next32.next_u32();
                    buff.splice(i * 4..((i + 1) * 4), dest.to_be_bytes());
                }
                assert_eq!(hex::encode(&buff), $expected_bytes[i]);

                // test next_64
                let mut mocked_rng_next64 = MockRng::<'_, $expander>::new(
                    msg.as_bytes(),
                    $dst,
                    count,
                    None,
                );

                let end_idx = count / 8;
                for i in 0..end_idx {
                    let dest = mocked_rng_next64.next_u64();
                    buff.splice(i * 8..((i + 1) * 8), dest.to_be_bytes());
                }
                assert_eq!(hex::encode(&buff), $expected_bytes[i]);
            }
        };
    }

    #[test]
    fn testing_sha256_mocked_rng() {
        let dst = &"QUUX-V01-CS02-with-expander-SHA256-128".as_bytes();
        test_mock_rng!(
            ExpandMsgXmd<Sha256>,
            dst,
            32,
            EXPECTED_SHA256_UNIFORM_BYTES
        );

        test_mock_rng!(
            ExpandMsgXmd<Sha256>,
            dst,
            128,
            EXPECTED_SHA256_UNIFORM_BYTES_LONG
        );
    }

    #[test]
    fn testing_shake256_mocked_rng() {
        let dst = &"QUUX-V01-CS02-with-expander-SHAKE256".as_bytes();
        test_mock_rng!(
            ExpandMsgXof<Shake256>,
            dst,
            32,
            EXPECTED_SHAKE256_UNIFORM_BYTES
        );

        test_mock_rng!(
            ExpandMsgXof<Shake256>,
            dst,
            128,
            EXPECTED_SHAKE256_UNIFORM_BYTES_LONG
        );
    }

    // hex encoded seed used to create the mocked random scalars
    const SEED: &str =
        "332e313431353932363533353839373933323338343632363433333833323739";

    const EXPECTED_SHA256_MOCKED_SCALARS: [&str; 10] = [
        "41b5e116922813fab50e1bcafd5a68f38c977fe4b01b3992424bc4ff1f1490bc",
        "57062c3eb0b030cbb45535bc7e8b3756288cfeee52ab6e2d1a56aedcfee668ba",
        "20a1f16c18342bc8650655783cd87b4491ce3986d0942e863d62053914bb3da1",
        "21ba43b4e1da365c6062b8cb00e3c22b0d49d68e30fae8a21ff9a476912a49ee",
        "2d34df08a57d8d7c6d3a8bdd34f45f0db539a4fc17b3e8948cb36360190248ed",
        "4840669faf2ab03e2b8a80d3ebc597cabfe35642680cec12f622daf63529be52",
        "3151326acfc6ec15b68ce67d52ce75abbe17d4224e78abb1c31f410f5664fc1a",
        "4cb74272bc2673959a3c72d992485057b1312cd8d2bf32747741324a92152c81",
        "2af0ebadecd3e43aefaafcfd3f426dca179140cdaf356a838381e584dfa0e4d1",
        "3aa6190cb2ae26ba433c3f6ff01504088cead97687f417f4bc80ac906201356c",
    ];

    const EXPECTED_SHAKE256_MOCKED_SCALARS: [&str; 10] = [
        "01b6e08fc79e13fad32d67f961ddb2e78d71efc3535ca36a5ff473f48266ce64",
        "0cdd099ab5ed28de45eccfff6ef8aca07572c771bcea4540ae1bd946c4f08824",
        "43353ad073f69d394b60a74ff6c3ec776fdb2d5ef3c74e5e2e1608fb108621a9",
        "035cec79e2a2f8110e521d5d58b8b905799505a87f287e80ec7b5597b278b3c1",
        "3fef09ffc2157bac6bebbd27f6a8fcea7d2220c319514aa23f3e7ea0c13307a4",
        "12a5e44260a0da4ce2e05fb02c7d004990f89cd30c80eca9fabe2f3ca09c5d6c",
        "5329ef2334622fde7f10c1963e19bd0a4fdaf39477b377be19cdcdc4b8b95fa9",
        "3fc6ae2d0c872e17be8444e6eb8197923c3f91372e5261e59d79b49983ef62d5",
        "732d59e95be946b589ffaa98f096bc51a8c0babf99f903303db1aca0645e4eee",
        "50ef4ed6a0aee7fda4d21df7a566bea1fc4eb1efe567affbc41795c9f044fa09",
    ];

    macro_rules! test_mock_rng_expected_values {
        (
            $seed:ident,
            $dst:ident,
            $expected_scalars:ident,
            $expander:ty) => {{
            let mut mocked_rng =
                MockRng::<'_, $expander>::new($seed, &$dst, 10, Some(48));

            let mut mocked_scalars: Vec<String> = Vec::new();
            for i in 0..10 {
                let mut buff = [0u8; 64];
                mocked_rng.fill_bytes(&mut buff[16..]);
                let scalar_i = Scalar::from_wide_bytes_be_mod_r(&buff);
                mocked_scalars.push(hex::encode(scalar_i.to_bytes_be()));

                assert_eq!(
                    hex::encode(scalar_i.to_bytes_be()),
                    $expected_scalars[i]
                );
            }
            // println!("{:?}", mocked_scalars);
        }};
    }

    #[test]
    fn test_sha256_expected_random_scalars() {
        let seed = hex::decode(SEED).unwrap();
        let dst = [
            sha_256_ciphersuite_id(),
            b"MOCK_RANDOM_SCALARS_DST_".to_vec(),
        ]
        .concat();

        test_mock_rng_expected_values!(
            seed,
            dst,
            EXPECTED_SHA256_MOCKED_SCALARS,
            ExpandMsgXmd<Sha256>
        )
    }

    #[test]
    fn test_shake256_expected_ranbom_scalars() {
        let seed = hex::decode(SEED).unwrap();
        let dst = [
            shake_256_ciphersuite_id(),
            b"MOCK_RANDOM_SCALARS_DST_".to_vec(),
        ]
        .concat();

        test_mock_rng_expected_values!(
            seed,
            dst,
            EXPECTED_SHAKE256_MOCKED_SCALARS,
            ExpandMsgXof<Shake256>
        )
    }
}
