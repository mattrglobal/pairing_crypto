use std::collections::HashMap;

use blstrs::Scalar;
use pairing_crypto::{
    bbs::{
        bls12_381::{OCTET_POINT_G1_LENGTH, OCTET_SCALAR_LENGTH},
        ciphersuites::bls12_381::{KeyPair, PublicKey, SecretKey},
        RandomScalars,
    },
    common::vec_to_byte_array,
};

use serde::{
    de::{self, MapAccess, Visitor},
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
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub key_dst: Vec<u8>,
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
            key_dst: Default::default(),
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
    #[serde(serialize_with = "serialize_signature_trace")]
    #[serde(deserialize_with = "deserialize_signature_trace")]
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
    #[serde(serialize_with = "serialize_messages")]
    #[serde(deserialize_with = "deserialize_messages")]
    pub messages: Vec<Vec<u8>>,
    #[serde(rename = "disclosedIndexes")]
    pub disclosed_indexes: Vec<usize>,
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
            messages: Default::default(),
            disclosed_indexes: Default::default(),
            proof: Default::default(),
            result: Default::default(),
            trace: ProofTrace::default(),
        }
    }
}

implement_case_name!(FixtureProof);

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NegativeProofFixture {
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
    pub disclosed_messages: Vec<(usize, Vec<u8>)>,
    pub proof: Vec<u8>,
    pub result: ExpectedResult,
}

impl From<FixtureGenInput> for NegativeProofFixture {
    fn from(val: FixtureGenInput) -> Self {
        Self {
            case_name: Default::default(),
            signer_public_key: Default::default(),
            header: val.header,
            presentation_header: val.presentation_header,
            disclosed_messages: Default::default(),
            proof: Default::default(),
            result: Default::default(),
        }
    }
}

implement_case_name!(NegativeProofFixture);

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

use pairing_crypto::bbs::{ProofTrace, SignatureTrace};

fn serialize_signature_trace<S>(
    trace: &SignatureTrace,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("SignatureTrace", 2)?;
    state.serialize_field("B", &hex::encode(trace.B))?;
    state.serialize_field("domain", &hex::encode(trace.domain))?;
    state.end()
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
fn deserialize_signature_trace<'de, D>(
    deserializer: D,
) -> Result<SignatureTrace, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize, Debug)]
    #[serde(field_identifier)]
    enum Field {
        B,
        domain,
    }

    struct SignatureTraceVisitor;
    impl<'de> Visitor<'de> for SignatureTraceVisitor {
        type Value = SignatureTrace;

        fn expecting(
            &self,
            formatter: &mut std::fmt::Formatter,
        ) -> std::fmt::Result {
            formatter.write_str("a SignatureTrace struct")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut B = None;
            let mut domain = None;

            while let Some(key) = map.next_key()? {
                match key {
                    Field::B => {
                        let v: &str = map.next_value()?;
                        B = Some(hex::decode(v).unwrap());
                    }
                    Field::domain => {
                        let v: &str = map.next_value()?;
                        domain = Some(hex::decode(v).unwrap());
                    }
                }
            }

            let B = B.ok_or_else(|| de::Error::missing_field("B"))?;
            let domain =
                domain.ok_or_else(|| de::Error::missing_field("domain"))?;
            Ok(SignatureTrace::new_from_vec(B, domain))
        }
    }

    const FIELDS: &'static [&'static str] = &["B", "domain"];
    deserializer.deserialize_struct("ProofTrace", FIELDS, SignatureTraceVisitor)
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ProofTrace")]
#[allow(non_snake_case)]
struct ProofTraceDef {
    /// The random scalars used during proof generation
    #[serde(serialize_with = "serialize_random_scalars")]
    #[serde(deserialize_with = "deserialize_random_scalars")]
    random_scalars: RandomScalars,
    /// The point A_bar calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    A_bar: [u8; OCTET_POINT_G1_LENGTH],
    /// The point B_bar calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    B_bar: [u8; OCTET_POINT_G1_LENGTH],
    /// The point D calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    D: [u8; OCTET_POINT_G1_LENGTH],
    /// The point T1 calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    T1: [u8; OCTET_POINT_G1_LENGTH],
    /// The point T2 calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    T2: [u8; OCTET_POINT_G1_LENGTH],
    /// The domain scalar value calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    domain: [u8; OCTET_SCALAR_LENGTH],
    /// The challenge scalar value calculated during proof generation
    #[serde(serialize_with = "hex::serde::serialize")]
    #[serde(deserialize_with = "hex::serde::deserialize")]
    challenge: [u8; OCTET_SCALAR_LENGTH],
}

fn serialize_random_scalars<S>(
    random_scalars: &RandomScalars,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("RandomScalars", 6)?;

    state
        .serialize_field("r1", &hex::encode(random_scalars.r1.to_bytes_be()))?;
    state
        .serialize_field("r2", &hex::encode(random_scalars.r2.to_bytes_be()))?;
    state.serialize_field(
        "e_tilde",
        &hex::encode(random_scalars.e_tilde.to_bytes_be()),
    )?;
    state.serialize_field(
        "r1_tilde",
        &hex::encode(random_scalars.r1_tilde.to_bytes_be()),
    )?;
    state.serialize_field(
        "r3_tilde",
        &hex::encode(random_scalars.r3_tilde.to_bytes_be()),
    )?;

    let m_tilde_octs: Vec<String> = random_scalars
        .m_tilde_scalars
        .iter()
        .map(|m_tilde| hex::encode(m_tilde.to_bytes_be()))
        .collect();
    state.serialize_field("m_tilde_scalars", &m_tilde_octs)?;
    state.end()
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
fn deserialize_random_scalars<'de, D>(
    deserializer: D,
) -> Result<RandomScalars, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize, Debug)]
    #[serde(field_identifier)]
    enum Field {
        r1,
        r2,
        e_tilde,
        r1_tilde,
        r3_tilde,
        m_tilde_scalars,
    }

    struct RandomScalarsVisitor;
    impl<'de> Visitor<'de> for RandomScalarsVisitor {
        type Value = RandomScalars;

        fn expecting(
            &self,
            formatter: &mut std::fmt::Formatter,
        ) -> std::fmt::Result {
            formatter.write_str("a RandomScalar struct")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut r1 = None;
            let mut r2 = None;
            let mut e_tilde = None;
            let mut r1_tilde = None;
            let mut r3_tilde = None;
            let mut m_tilde_scalars = None;

            while let Some(key) = map.next_key()? {
                match key {
                    Field::r1 => {
                        let v: &str = map.next_value()?;
                        r1 = Some(hex::decode(v).unwrap());
                    }
                    Field::r2 => {
                        let v: &str = map.next_value()?;
                        r2 = Some(hex::decode(v).unwrap());
                    }
                    Field::e_tilde => {
                        let v: &str = map.next_value()?;
                        e_tilde = Some(hex::decode(v).unwrap());
                    }
                    Field::r1_tilde => {
                        let v: &str = map.next_value()?;
                        r1_tilde = Some(hex::decode(v).unwrap());
                    }
                    Field::r3_tilde => {
                        let v: &str = map.next_value()?;
                        r3_tilde = Some(hex::decode(v).unwrap());
                    }
                    Field::m_tilde_scalars => {
                        let v: Vec<&str> = map.next_value()?;
                        let m_tildes: Vec<Vec<u8>> =
                            v.iter().map(|m| hex::decode(m).unwrap()).collect();
                        m_tilde_scalars = Some(m_tildes);
                    }
                }
            }

            let r1 = r1.ok_or_else(|| de::Error::missing_field("r1"))?;
            let r2 = r2.ok_or_else(|| de::Error::missing_field("r2"))?;
            let e_tilde =
                e_tilde.ok_or_else(|| de::Error::missing_field("e_tilde"))?;
            let r1_tilde =
                r1_tilde.ok_or_else(|| de::Error::missing_field("r1_tilde"))?;
            let r3_tilde =
                r3_tilde.ok_or_else(|| de::Error::missing_field("r3_tilde"))?;
            let m_tilde_scalars = m_tilde_scalars
                .ok_or_else(|| de::Error::missing_field("m_tilde_scalars"))?;

            let m_tilde_scalars = m_tilde_scalars
                .iter()
                .map(|m| {
                    Scalar::from_bytes_be(
                        &vec_to_byte_array::<OCTET_SCALAR_LENGTH>(&m).unwrap(),
                    )
                    .unwrap()
                })
                .collect();

            Ok(RandomScalars {
                r1: Scalar::from_bytes_be(
                    &vec_to_byte_array::<OCTET_SCALAR_LENGTH>(&r1).unwrap(),
                )
                .unwrap(),
                r2: Scalar::from_bytes_be(
                    &vec_to_byte_array::<OCTET_SCALAR_LENGTH>(&r2).unwrap(),
                )
                .unwrap(),
                e_tilde: Scalar::from_bytes_be(
                    &vec_to_byte_array::<OCTET_SCALAR_LENGTH>(&e_tilde)
                        .unwrap(),
                )
                .unwrap(),
                r1_tilde: Scalar::from_bytes_be(
                    &vec_to_byte_array::<OCTET_SCALAR_LENGTH>(&r1_tilde)
                        .unwrap(),
                )
                .unwrap(),
                r3_tilde: Scalar::from_bytes_be(
                    &vec_to_byte_array::<OCTET_SCALAR_LENGTH>(&r3_tilde)
                        .unwrap(),
                )
                .unwrap(),
                m_tilde_scalars,
            })
        }
    }

    const FIELDS: &'static [&'static str] = &[
        "r1",
        "r2",
        "e_tilde",
        "r1_tilde",
        "r3_tilde",
        "m_tilde_scalars",
    ];
    deserializer.deserialize_struct(
        "RandomScalars",
        FIELDS,
        RandomScalarsVisitor,
    )
}
