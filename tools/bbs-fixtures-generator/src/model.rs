use std::collections::HashMap;

use pairing_crypto::bbs::ciphersuites::bls12_381::{
    suite_constants::{OCTET_POINT_G1_LENGTH, OCTET_SCALAR_LENGTH},
    KeyPair,
    PublicKey,
    SecretKey,
};

use blstrs::Scalar;
use core::fmt;
use serde::{
    de::{self, MapAccess},
    ser::{SerializeMap, SerializeSeq, SerializeStruct},
    Deserialize,
    Deserializer,
    Serializer,
};
use serde_derive::Serialize;

pub trait CaseName {
    fn derive_case_name(&mut self) {}
}

macro_rules! implement_case_name {
    ($t:ident) => {
        impl CaseName for $t {
            fn derive_case_name(&mut self) {
                match self.result.valid {
                    true => {
                        self.case_name = format!("valid {}", self.case_name)
                    }
                    false => {
                        self.case_name = format!(
                            "invalid {} ({})",
                            self.case_name,
                            self.result.reason.as_ref().unwrap()
                        )
                    }
                }
            }
        }
    };
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FixtureKeyGen {
    pub case_name: String,
    pub key_material: String,
    pub key_info: String,
    #[serde(serialize_with = "serialize_key_pair")]
    #[serde(deserialize_with = "deserialize_key_pair")]
    pub key_pair: KeyPair,
}
impl CaseName for FixtureKeyGen {}

impl From<FixtureGenInput> for FixtureKeyGen {
    fn from(value: FixtureGenInput) -> Self {
        Self {
            case_name: Default::default(),
            key_material: hex::encode(value.key_ikm),
            key_info: hex::encode(value.key_info),
            key_pair: Default::default(),
        }
    }
}

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
    pub key_ikm: Vec<u8>,
    pub spare_key_ikm: Vec<u8>,
    pub key_info: Vec<u8>,
    pub header: Vec<u8>,
    pub presentation_header: Vec<u8>,
    pub messages: Vec<Vec<u8>>,
}

impl From<TestAsset> for FixtureGenInput {
    fn from(t: TestAsset) -> Self {
        let messages = t
            .messages
            .iter()
            .map(|m| hex::decode(m).unwrap())
            .collect::<Vec<Vec<u8>>>();

        Self {
            key_ikm: t.key_ikm,
            spare_key_ikm: t.spare_key_ikm,
            key_info: t.key_info,
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
    #[serde(with = "SignatureTraceDef")]
    pub trace: SignatureTrace,
}

impl From<FixtureGenInput> for FixtureSignature {
    fn from(val: FixtureGenInput) -> Self {
        Self {
            case_name: Default::default(),
            key_pair: Default::default(),
            header: val.header,
            messages: val.messages,
            signature: Default::default(),
            result: Default::default(),
            trace: SignatureTrace::default(),
        }
    }
}

implement_case_name!(FixtureSignature);

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FixtureProof {
    pub case_name: String,
    #[serde(serialize_with = "serialize_public_key")]
    #[serde(deserialize_with = "deserialize_public_key")]
    pub signer_public_key: PublicKey,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub signature: Vec<u8>,
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
    #[serde(with = "ProofTraceDef")]
    pub trace: ProofTrace,
}

impl From<FixtureGenInput> for FixtureProof {
    fn from(val: FixtureGenInput) -> Self {
        Self {
            case_name: Default::default(),
            signer_public_key: Default::default(),
            signature: Default::default(),
            header: val.header,
            presentation_header: val.presentation_header,
            disclosed_messages: Default::default(),
            proof: Default::default(),
            result: Default::default(),
            trace: ProofTrace::default(),
        }
    }
}

implement_case_name!(FixtureProof);

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

impl CaseName for FixtureH2s {}

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

impl CaseName for FixtureMapMessageToScalar {}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FixtureMockedRng {
    pub case_name: String,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub seed: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub dst: Vec<u8>,
    pub count: usize,
    pub mocked_scalars: Vec<String>,
}

impl CaseName for FixtureMockedRng {}

fn serialize_key_pair<S>(
    key_pair: &KeyPair,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("KeyPair", 2)?;
    state.serialize_field(
        "secretKey",
        &hex::encode(key_pair.secret_key.to_bytes()),
    )?;
    state.serialize_field(
        "publicKey",
        &hex::encode(key_pair.public_key.to_octets()),
    )?;
    state.end()
}

pub fn deserialize_key_pair<'de, D>(
    deserializer: D,
) -> Result<KeyPair, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(field_identifier, rename_all = "camelCase")]
    enum KeyPairField {
        SecretKey,
        PublicKey,
    }

    struct KeyPairVisitor;
    impl<'de> de::Visitor<'de> for KeyPairVisitor {
        type Value = KeyPair;

        fn expecting(
            &self,
            formatter: &mut std::fmt::Formatter,
        ) -> std::fmt::Result {
            formatter.write_str("struct KeyPair")
        }

        fn visit_map<V>(self, mut map: V) -> Result<KeyPair, V::Error>
        where
            V: MapAccess<'de>,
        {
            macro_rules! check_duplicate_and_set_field {
                ($value:ident) => {{
                    if $value.is_some() {
                        return Err(de::Error::duplicate_field("$value"));
                    }
                    $value = Some(map.next_value()?);
                }};
            }
            let mut secret_key = None;
            let mut public_key = None;

            while let Some(key) = map.next_key()? {
                match key {
                    KeyPairField::SecretKey => {
                        check_duplicate_and_set_field!(secret_key)
                    }
                    KeyPairField::PublicKey => {
                        check_duplicate_and_set_field!(public_key)
                    }
                }
            }

            let secret_key: &str = secret_key
                .ok_or_else(|| de::Error::missing_field("secretKey"))?;
            let public_key: &str = public_key
                .ok_or_else(|| de::Error::missing_field("publicKey"))?;

            let secret_key =
                SecretKey::from_vec(&hex::decode(secret_key).unwrap()).unwrap();
            let public_key =
                PublicKey::from_vec(&hex::decode(public_key).unwrap()).unwrap();

            Ok(KeyPair {
                secret_key,
                public_key,
            })
        }
    }
    const FIELDS: &[&str] = &["secretKey", "publicKey"];
    deserializer.deserialize_struct("KeyPair", FIELDS, KeyPairVisitor)
}

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

fn serialize_messages<S>(
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

fn serialize_disclosed_messages<S>(
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

use pairing_crypto::bbs::types::{ProofTrace, RandomScalars, SignatureTrace};

#[derive(Serialize, Deserialize)]
#[serde(remote = "SignatureTrace")]
#[allow(non_snake_case)]
pub struct SignatureTraceDef {
    /// The point B calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub B: [u8; OCTET_POINT_G1_LENGTH],
    /// The domain scalar value calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub domain: [u8; OCTET_SCALAR_LENGTH],
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "RandomScalars")]
pub struct RandomScalarsDef {
    /// The r1 random scalar
    #[serde(serialize_with = "serialize_scalar")]
    #[serde(deserialize_with = "deserialize_scalar")]
    pub r1: Scalar,
    /// The r1~ random scalar (blinding the r1 value)
    #[serde(serialize_with = "serialize_scalar")]
    #[serde(deserialize_with = "deserialize_scalar")]
    pub r2_tilde: Scalar,
    /// The r3~ random scalar (blinding the r3 value)
    #[serde(serialize_with = "serialize_scalar")]
    #[serde(deserialize_with = "deserialize_scalar")]
    pub z_tilde: Scalar,
    /// The list of m~_i random scalars (blinding the undisclosed messages)
    #[serde(serialize_with = "serialize_scalars_vec")]
    #[serde(deserialize_with = "deserialize_scalars_vec")]
    pub m_tilde_scalars: Vec<Scalar>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ProofTrace")]
#[allow(non_snake_case)]
pub struct ProofTraceDef {
    /// The random scalars used during proof generation
    #[serde(with = "RandomScalarsDef")]
    pub random_scalars: RandomScalars,
    /// The point A_bar calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub A_bar: [u8; OCTET_POINT_G1_LENGTH],
    /// The point B_bar calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub B_bar: [u8; OCTET_POINT_G1_LENGTH],
    /// The point T calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub T: [u8; OCTET_POINT_G1_LENGTH],
    /// The domain scalar value calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub domain: [u8; OCTET_SCALAR_LENGTH],
    /// The challenge scalar value calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub challenge: [u8; OCTET_SCALAR_LENGTH],
}

pub(crate) fn serialize_scalar<S>(
    scalar: &Scalar,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let res = hex::encode(scalar.to_bytes_be());
    serializer.serialize_str(&res)
}

pub(crate) fn serialize_scalars_vec<S>(
    scalars: &Vec<Scalar>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(scalars.len()))?;
    for scalar in scalars {
        seq.serialize_element(&hex::encode(scalar.to_bytes_be()))?;
    }
    seq.end()
}

pub(crate) fn deserialize_scalar<'de, D>(
    deserializer: D,
) -> Result<Scalar, D::Error>
where
    D: Deserializer<'de>,
{
    struct ScalarVisitor;

    impl<'de> de::Visitor<'de> for ScalarVisitor {
        type Value = Scalar;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a Scalar value")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = hex::decode(v).expect("Hex decoding failed");
            let b = <[u8; 32]>::try_from(bytes).unwrap();

            let scalar = Scalar::from_bytes_be(&b);

            if scalar.is_none().unwrap_u8() == 1u8 {
                return Err(E::custom("Invalid Scalar value"));
            };

            Ok(scalar.unwrap())
        }
    }

    deserializer.deserialize_str(ScalarVisitor)
}

fn deserialize_scalars_vec<'de, D>(
    deserializer: D,
) -> Result<Vec<Scalar>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ScalarsVecVisitor;

    impl<'de> de::Visitor<'de> for ScalarsVecVisitor {
        type Value = Vec<Scalar>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of Scalar values")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut scalars_vec =
                Vec::with_capacity(seq.size_hint().unwrap_or(0));

            while let Some(scalar_hex) = seq.next_element::<String>()? {
                let scalar_bytes = <[u8; 32]>::try_from(
                    hex::decode(scalar_hex)
                        .expect("Scalar hex decoding failed"),
                )
                .unwrap();

                let scalar = Scalar::from_bytes_be(&scalar_bytes);

                if scalar.is_none().unwrap_u8() == 1u8 {
                    return Err(de::Error::custom("Invalid Scalar value"));
                }

                scalars_vec.push(scalar.unwrap())
            }

            Ok(scalars_vec)
        }
    }

    deserializer.deserialize_seq(ScalarsVecVisitor)
}
