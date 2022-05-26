use super::constants::{g1_affine_compressed_size, scalar_size};
use crate::curves::bls12_381::{G1Affine, G1Projective, Scalar};
use group::Curve;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::CtOption;

macro_rules! scalar_wrapper {
    ($(#[$docs:meta])*
     $name:ident) => {
        $(#[$docs])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize, Serialize)]
        pub struct $name(pub Scalar);

        impl Default for $name {
            fn default() -> Self {
                use ff::Field;
                Self(Scalar::zero())
            }
        }

        impl $name {
            /// The number of bytes needed to represent this struct
            pub const SIZE_BYTES: usize = scalar_size();

            /// Generate a random struct
            pub fn random(rng: impl rand_core::RngCore) -> Self {
                use ff::Field;
                Self(Scalar::random(rng))
            }

            /// Convert the secret key to a big-endian representation
            pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
                self.0.to_bytes_be()
            }

            /// Convert a big-endian representation of the secret key
            pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> CtOption<Self> {
                Scalar::from_bytes_be(bytes).map($name)
            }

            /// Convert a 48 byte digest into a struct
            pub fn from_okm(bytes: &[u8; g1_affine_compressed_size()]) -> Self {
                Self(Scalar::from_okm(bytes))
            }

            /// Hash arbitrary data to this struct
            pub fn hash<B: AsRef<[u8]>>(_data: B) -> Self {
                todo!()
            }

        }
    };
}

scalar_wrapper!(
    /// A challenge generated by fiat-shamir heuristic
    Challenge
);

scalar_wrapper!(
    /// A message to be signed
    Message
);

scalar_wrapper!(
    /// A nonce that is used for zero-knowledge proofs
    Nonce
);

scalar_wrapper!(
    /// A presentation message that is used for zero-knowledge proofs
    PresentationMessage
);

scalar_wrapper!(
    /// A blinding factor for blinding a signature
    SignatureBlinding
);

/// Two types of hidden messages
#[derive(Copy, Clone, Debug)]
pub enum HiddenMessage {
    /// Indicates the message is hidden and no other work is involved
    ///     so a blinding factor will be generated specific to this proof
    ProofSpecificBlinding(Message),
    /// Indicates the message is hidden but it is involved with other proofs
    ///     like boundchecks, set memberships or inequalities, so the blinding
    /// factor     is provided from an external source.
    ExternalBlinding(Message, Nonce),
}

/// A message classification by the prover
#[derive(Copy, Clone, Debug)]
pub enum ProofMessage {
    /// Message will be revealed to a verifier
    Revealed(Message),
    /// Message will be hidden from a verifier
    Hidden(HiddenMessage),
}

impl ProofMessage {
    /// Extract the internal message
    pub fn get_message(&self) -> Message {
        match *self {
            ProofMessage::Revealed(r) => r,
            ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(p)) => p,
            ProofMessage::Hidden(HiddenMessage::ExternalBlinding(p, _)) => p,
        }
    }
}

/// Represents one or more commitments as
/// x * G1 + ...
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Commitment(pub G1Projective);

impl Serialize for Commitment {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Commitment {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = G1Projective::deserialize(d)?;
        Ok(Self(p))
    }
}

impl Commitment {
    /// Number of bytes needed to represent the commitment
    pub const SIZE_BYTES: usize = g1_affine_compressed_size();

    /// Get the byte sequence that represents this signature
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        self.0.to_affine().to_compressed()
    }

    /// Convert a big-endian representation of the commitment
    pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> CtOption<Self> {
        G1Affine::from_compressed(bytes).map(|p| Self(G1Projective::from(&p)))
    }
}
