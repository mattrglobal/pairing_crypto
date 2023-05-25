use std::collections::HashMap;

use crate::sha256_bbs_key_gen_tool;
use pairing_crypto::bbs::ciphersuites::bls12_381::{
    KeyPair,
    PublicKey,
    SecretKey,
};
use serde::{
    de::{self, MapAccess},
    ser::{SerializeMap, SerializeSeq, SerializeStruct},
    Deserialize,
    Deserializer,
    Serializer,
};
use serde_derive::Serialize;
use crate::util::{serialize_key_pair_impl, deserialize_key_pair_impl};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TestAsset {
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub key_ikm: Vec<u8>,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub spare_key_ikm: Vec<u8>,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub key_info: Vec<u8>,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub header: Vec<u8>,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub presentation_header: Vec<u8>,
    pub messages: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct FixtureGenInput {
    pub key_pair: KeyPair,
    pub spare_key_pair: KeyPair,
    pub header: Vec<u8>,
    pub presentation_header: Vec<u8>,
    pub messages: Vec<Vec<u8>>,
}

impl From<TestAsset> for FixtureGenInput {
    fn from(t: TestAsset) -> Self {
        let key_pair =
            sha256_bbs_key_gen_tool(&t.key_ikm, &t.key_info).unwrap();

        let spare_key_pair =
            sha256_bbs_key_gen_tool(&t.spare_key_ikm, &t.key_info).unwrap();

        let messages = t
            .messages
            .iter()
            .map(|m| hex::decode(m).unwrap())
            .collect::<Vec<Vec<u8>>>();

        Self {
            key_pair,
            spare_key_pair,
            header: t.header,
            presentation_header: t.presentation_header,
            messages,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ExpectedResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FixtureSignature {
    pub case_name: String,
    #[serde(serialize_with = "serialize_key_pair")]
    #[serde(deserialize_with = "deserialize_key_pair")]
    #[serde(rename = "signerKeyPair")]
    pub key_pair: KeyPair,
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

impl From<FixtureGenInput> for FixtureSignature {
    fn from(val: FixtureGenInput) -> Self {
        Self {
            case_name: Default::default(),
            key_pair: val.key_pair,
            header: val.header,
            messages: val.messages,
            signature: Default::default(),
            result: Default::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FixtureProof {
    pub case_name: String,
    #[serde(serialize_with = "serialize_public_key")]
    #[serde(deserialize_with = "deserialize_public_key")]
    pub signer_public_key: PublicKey,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub header: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub presentation_header: Vec<u8>,
    #[serde(serialize_with = "serialize_disclosed_messages")]
    #[serde(deserialize_with = "deserialize_disclosed_messages")]
    #[serde(rename = "revealedMessages")]
    pub disclosed_messages: Vec<(usize, Vec<u8>)>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub proof: Vec<u8>,
    pub result: ExpectedResult,
}

impl From<FixtureGenInput> for FixtureProof {
    fn from(val: FixtureGenInput) -> Self {
        Self {
            case_name: Default::default(),
            signer_public_key: val.key_pair.public_key,
            header: val.header,
            presentation_header: val.presentation_header,
            disclosed_messages: Default::default(),
            proof: Default::default(),
            result: Default::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MessageToScalarFixtureCase {
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub message: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub scalar: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FixtureH2s {
    pub case_name: String,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub message: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub dst: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub scalar: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FixtureMapMessageToScalar {
    pub case_name: String,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub dst: Vec<u8>,
    #[serde(serialize_with = "serialize_message_to_scalar_cases")]
    pub cases: Vec<MessageToScalarFixtureCase>,
}


serialize_key_pair_impl!(serialize_key_pair, KeyPair);
deserialize_key_pair_impl!(deserialize_key_pair, KeyPair, SecretKey, PublicKey);

fn serialize_public_key<S>(
    public_key: &PublicKey,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(public_key.to_octets()))
}

pub fn deserialize_public_key<'de, D>(
    deserializer: D,
) -> Result<PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let public_key = String::deserialize(deserializer)?;
    Ok(PublicKey::from_vec(&hex::decode(public_key).unwrap()).unwrap())
}

pub fn serialize_messages<S>(
    messages: &Vec<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(messages.len()))?;
    for m in messages {
        seq.serialize_element(&hex::encode(m))?;
    }
    seq.end()
}

pub fn deserialize_messages<'de, D>(
    deserializer: D,
) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct MessagesVisitor;
    impl<'de> de::Visitor<'de> for MessagesVisitor {
        type Value = Vec<Vec<u8>>;

        fn expecting(
            &self,
            formatter: &mut std::fmt::Formatter,
        ) -> std::fmt::Result {
            formatter.write_str("sequence of byte-array")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(i) = seq.next_element::<&str>()? {
                vec.push(hex::decode(i).unwrap());
            }
            Ok(vec)
        }
    }
    deserializer.deserialize_seq(MessagesVisitor)
}

pub fn serialize_disclosed_messages<S>(
    disclosed_messages: &Vec<(usize, Vec<u8>)>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(disclosed_messages.len()))?;
    for (i, m) in disclosed_messages {
        map.serialize_entry(i, &hex::encode(m))?;
    }
    map.end()
}

pub fn deserialize_disclosed_messages<'de, D>(
    deserializer: D,
) -> Result<Vec<(usize, Vec<u8>)>, D::Error>
where
    D: Deserializer<'de>,
{
    struct DisclosedMessagesVisitor;

    impl<'de> de::Visitor<'de> for DisclosedMessagesVisitor {
        type Value = Vec<(usize, Vec<u8>)>;

        fn expecting(
            &self,
            formatter: &mut std::fmt::Formatter,
        ) -> std::fmt::Result {
            formatter.write_str("map (usize, byte-array)")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map: HashMap<usize, &str> =
                HashMap::with_capacity(access.size_hint().unwrap_or(0));

            while let Some((key, value)) = access.next_entry()? {
                map.insert(key, value);
            }

            Ok(map
                .into_iter()
                .map(|(k, v)| (k, hex::decode(v).unwrap()))
                .collect())
        }
    }

    deserializer.deserialize_map(DisclosedMessagesVisitor)
}

pub fn serialize_message_to_scalar_cases<S>(
    cases: &Vec<MessageToScalarFixtureCase>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(cases.len()))?;
    for case in cases {
        seq.serialize_element(&case)?;
    }
    seq.end()
}
