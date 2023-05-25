use pairing_crypto::{
        bls::ciphersuites::bls12_381::{KeyPair, SecretKey, PublicKey},
        bbs_bound::ciphersuites::bls12_381_bbs_g1_bls_sig_g2_sha_256::{
            BbsKeyPair, BbsSecretKey, BbsPublicKey
        }
};

use serde_derive::Serialize;
use serde::{
    de::{self, MapAccess},
    ser::SerializeStruct,
    Deserialize,
    Deserializer,
    Serializer,
};
use bbs_fixtures_generator::{
    serialize_key_pair_impl,
    deserialize_key_pair_impl,
    ExpectedResult,
    TestAsset,
    sha256_bbs_key_gen_tool,
    serialize_messages,
    deserialize_messages,
    serialize_disclosed_messages,
    deserialize_disclosed_messages
};

#[derive(Debug, Default, Clone)]
pub struct BoundFixtureGenInput {
    pub bbs_key_pair: BbsKeyPair,
    pub bls_key_pair: KeyPair,
    pub header: Vec<u8>,
    pub presentation_header: Vec<u8>,
    pub messages: Vec<Vec<u8>>,
}

impl From<TestAsset> for BoundFixtureGenInput {
    fn from(t: TestAsset) -> Self {
        let bbs_key_pair = sha256_bbs_key_gen_tool(&t.key_ikm, &t.key_info).unwrap();
        let bls_key_pair = KeyPair::new(&t.key_ikm, &t.key_info).unwrap();

        let messages = t
            .messages
            .iter()
            .map(|m| hex::decode(m).unwrap())
            .collect::<Vec<Vec<u8>>>();

            Self {
                bbs_key_pair,
                bls_key_pair,
                header: t.header,
                presentation_header: t.presentation_header,
                messages,
            }
    }
}


serialize_key_pair_impl!(serialize_key_pair, KeyPair);
deserialize_key_pair_impl!(deserialize_key_pair, KeyPair, SecretKey, PublicKey);

serialize_key_pair_impl!(serialize_bbs_key_pair, BbsKeyPair);
deserialize_key_pair_impl!(deserialize_bbs_key_pair, BbsKeyPair, BbsSecretKey, BbsPublicKey);

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct FixtureKeyPoP {
    pub case_name: String,
    #[serde(serialize_with = "serialize_key_pair")]
    #[serde(deserialize_with = "deserialize_key_pair")]
    pub bls_key_pair: KeyPair,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub aud: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub dst: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub extra_info: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub pop: Vec<u8>
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct FixtureBoundSignature {
    pub case_name: String,
    #[serde(serialize_with = "serialize_bbs_key_pair")]
    #[serde(deserialize_with = "deserialize_bbs_key_pair")]
    pub bbs_key_pair: BbsKeyPair,
    #[serde(serialize_with = "serialize_key_pair")]
    #[serde(deserialize_with = "deserialize_key_pair")]
    pub bls_key_pair: KeyPair,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub header: Vec<u8>,
    #[serde(serialize_with = "serialize_messages")]
    #[serde(deserialize_with = "deserialize_messages")]
    pub messages: Vec<Vec<u8>>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub signature: Vec<u8>,
    pub result: ExpectedResult,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct FixtureBoundProof {
    pub case_name: String,
    #[serde(serialize_with = "serialize_public_key")]
    #[serde(deserialize_with = "deserialize_public_key")]
    pub bbs_pub_key: BbsPublicKey,
    #[serde(serialize_with = "serialize_key_pair")]
    #[serde(deserialize_with = "deserialize_key_pair")]
    pub bls_key_pair: KeyPair,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub header: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub presentation_header: Vec<u8>,
    #[serde(serialize_with = "serialize_disclosed_messages")]
    #[serde(deserialize_with = "deserialize_disclosed_messages")]
    pub disclosed_messages: Vec<(usize, Vec<u8>)>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub signature: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub proof: Vec<u8>,
    pub result: ExpectedResult,
}

fn serialize_public_key<S>(
    public_key: &BbsPublicKey,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(public_key.to_octets()))
}

pub fn deserialize_public_key<'de, D>(
    deserializer: D,
) -> Result<BbsPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let public_key = String::deserialize(deserializer)?;
    Ok(BbsPublicKey::from_vec(&hex::decode(public_key).unwrap()).unwrap())
}