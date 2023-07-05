use blstrs::hash_to_curve::{
    ExpandMessage,
    ExpandMessageState,
    InitExpandMessage,
};
use rand::{CryptoRng, RngCore};

pub const MOCKED_RNG_SEED: &str = "3.141592653589793238462643383279"; // 30 first digits of pi
pub const MOCKED_RNG_DST: &str = "MOCK_RANDOM_SCALARS_DST_";

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
        let seed = seed.as_ref();
        let expand_len = expand_len.unwrap_or(1_usize);
        let expand_len = count * expand_len;
        let init_v = E::init_expand(seed, dst, expand_len);
        MockRng { v: init_v }
    }

    pub fn fill(&mut self, dest: &mut [u8]) -> usize {
        self.v.read_into(dest)
    }

    pub fn is_empty(&self) -> bool {
        self.v.remain() == 0
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
                "{} random bytes are remaining, but {} where requested",
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

    // sha256 based hash, output len = 32
    const EXPECTED_SHA256_UNIFORM_BYTES: [&str; 5] = [
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
        "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
        "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
        "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9",
        "4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c",
    ];

    // sha256 based hash, output len = 128
    const EXPECTED_SHA256_UNIFORM_BYTES_LONG: [&str; 5] = [
        "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
        "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
        "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df",
        "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a",
        "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487"
    ];

    // shake256 based hash, output len = 32
    const EXPECTED_SHAKE256_UNIFORM_BYTES: [&str; 5] = [
        "2ffc05c48ed32b95d72e807f6eab9f7530dd1c2f013914c8fed38c5ccc15ad76",
        "b39e493867e2767216792abce1f2676c197c0692aed061560ead251821808e07",
        "245389cf44a13f0e70af8665fe5337ec2dcd138890bb7901c4ad9cfceb054b65",
        "719b3911821e6428a5ed9b8e600f2866bcf23c8f0515e52d6c6c019a03f16f0e",
        "9181ead5220b1963f1b5951f35547a5ea86a820562287d6ca4723633d17ccbbc",
    ];

    // shake256 based hash, output len = 128
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
        "685e3caf71dcebe9c1c8ade572714cacfa8021ecdc0087f088ddf9d779ee6497",
        "3f03740ac2195b6e690f947a4868d18a0ffc740f0cd662af065de7c82ce47bca",
        "7243343f651b84dd385374df66239721cd72be386ace284582e50f3a7f7a41fd",
        "719391a40fb0d859142f3a407724d8d9f0bec2a29e2a13dd72373a08be8b8ebe",
        "12c52b9360297ba351a6af102f85811100f34f85f2cb1ae84d51c864673180fb",
        "03670bd1cbf4aa22ab64594f509edcc8b10078b94681de34d46f4add973c095b",
        "5c6f556cd9dadb28115b3d800f3252d88a5cd5f77fe9c48c2737a3731f87b389",
        "6f2a91c5faa4d1833fc20d61a9408000e34b9cb4117bf01c84e9dc87e1edb5af",
        "3e2f4c7553113858fef77769bc3db8a4fe75e0d04f29487e3eab89cc994e461b",
        "27a48d2128295df61613e065e8640b20a457a1687979363f8746366ff7c3c082",
    ];

    const EXPECTED_SHAKE256_MOCKED_SCALARS: [&str; 10] = [
        "4da25c0e59e761a994c4d71d2e844fada4d83e6be5485b0ea38ce64ee244565f",
        "38fbbb94037248f48f26434de7b23a6a9e10b8fb3a0e9a39140e551f9c398938",
        "4b9eaac397a99f42beb5117e278bb934d8d32acd40b84b1fe4a284517f98df4b",
        "6d8f213126ab25204faf6aa52d72727ccc22500bd02e779b6048a84d6193f31a",
        "4f727d3540549f780cf9d1a6268a81c027241a6e3e07ce278c06fc3cf0f700ef",
        "573beaa4601aae2f85401d821cbcc02cad34e82119f23df455b40f83e5cf5459",
        "6e671af69be456e7e5fe9c864e1faee35e65e84c8686b62d9987966d7240d529",
        "1d58f4d7f825e6da79855a28c91e675ac121d66c65d7447b6be19137c302be76",
        "312d9bd8cc421b6e122f636f48c37b53c70f44c37fa39ccafe2a6a4a4cdd265b",
        "581bc51ae19b34b5192d2d0aa09ffe2162febc284e752ba549aba4e0007cb34c",
    ];

    macro_rules! test_mock_rng_expected_values {
        (
            $seed:ident,
            $dst:ident,
            $expected_scalars:ident,
            $expander:ty) => {{
            const MOCKED_SCALARS_NO: usize = 10;
            let mut mocked_rng = MockRng::<'_, $expander>::new(
                $seed,
                &$dst,
                MOCKED_SCALARS_NO,
                Some(48),
            );

            let mut mocked_scalars: Vec<String> = Vec::new();
            for i in 0..MOCKED_SCALARS_NO {
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
