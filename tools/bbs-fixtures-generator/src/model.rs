use pairing_crypto::bbs::{
    ciphersuites::bls12_381::KeyPair,
    core::key_pair::PublicKey,
};
use serde::{
    ser::{SerializeMap, SerializeSeq, SerializeStruct},
    Serializer,
};
use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TestAsset {
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub key_ikm: Vec<u8>,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub key_info: Vec<u8>,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub header: Vec<u8>,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub presentation_message: Vec<u8>,
    pub messages: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct FixtureGenInput {
    pub key_pair: KeyPair,
    pub header: Vec<u8>,
    pub presentation_message: Vec<u8>,
    pub messages: Vec<Vec<u8>>,
}

impl From<TestAsset> for FixtureGenInput {
    fn from(t: TestAsset) -> Self {
        let key_pair = KeyPair::new(&t.key_ikm, &t.key_info).unwrap();

        let messages = t
            .messages
            .iter()
            .map(|m| hex::decode(m).unwrap())
            .collect::<Vec<Vec<u8>>>();

        Self {
            key_pair,
            header: t.header,
            presentation_message: t.presentation_message,
            messages,
        }
    }
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct ExpectedResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FixtureSignature {
    pub case_name: String,
    #[serde(serialize_with = "serialize_key_pair")]
    #[serde(rename = "signerKeyPair")]
    pub key_pair: KeyPair,
    #[serde(serialize_with = "hex::serde::serialize")]
    pub header: Vec<u8>,
    #[serde(serialize_with = "serialize_messages")]
    pub messages: Vec<Vec<u8>>,
    #[serde(serialize_with = "hex::serde::serialize")]
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

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FixtureProof {
    pub case_name: String,
    #[serde(serialize_with = "serialize_public_key")]
    pub signer_public_key: PublicKey,
    #[serde(serialize_with = "hex::serde::serialize")]
    pub header: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize")]
    pub presentation_message: Vec<u8>,
    #[serde(serialize_with = "serialize_disclosed_messages")]
    pub disclosed_messages: Vec<(usize, Vec<u8>)>,
    pub total_message_count: usize,
    #[serde(serialize_with = "hex::serde::serialize")]
    pub proof: Vec<u8>,
    pub result: ExpectedResult,
}

impl From<FixtureGenInput> for FixtureProof {
    fn from(val: FixtureGenInput) -> Self {
        Self {
            case_name: Default::default(),
            signer_public_key: val.key_pair.public_key,
            header: val.header,
            presentation_message: val.presentation_message,
            disclosed_messages: Default::default(),
            total_message_count: Default::default(),
            proof: Default::default(),
            result: Default::default(),
        }
    }
}

fn serialize_key_pair<S>(
    key_pair: &KeyPair,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("KeyPair", 2)?;
    state.serialize_field(
        "secret_key",
        &hex::encode(&key_pair.secret_key.to_bytes()),
    )?;
    state.serialize_field(
        "public_key",
        &hex::encode(&key_pair.public_key.to_octets()),
    )?;
    state.end()
}

fn serialize_public_key<S>(
    public_key: &PublicKey,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(&public_key.to_octets()))
}

fn serialize_messages<S>(
    messages: &Vec<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(messages.len()))?;
    for m in messages {
        seq.serialize_element(&hex::encode(&m))?;
    }
    seq.end()
}

fn serialize_disclosed_messages<S>(
    disclosed_messages: &Vec<(usize, Vec<u8>)>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(disclosed_messages.len()))?;
    for (i, m) in disclosed_messages {
        map.serialize_entry(i, &hex::encode(&m))?;
    }
    map.end()
}
