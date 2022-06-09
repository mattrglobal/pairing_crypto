use super::constants::{g1_affine_compressed_size, scalar_size};
use crate::{
    bbs::core::hash_utils::map_message_to_scalar_as_hash,
    curves::bls12_381::{G1Affine, G1Projective, Scalar},
    error::Error,
};
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
            /// The number of bytes needed to represent this type.
            pub const SIZE_BYTES: usize = scalar_size();

            /// Generate a random value for this type.
            pub fn random<R: rand_core::RngCore>(rng: &mut R) -> Self {
                use ff::Field;
                Self(Scalar::random(rng))
            }

            /// Convert this type to a big-endian representation.
            pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
                self.0.to_bytes_be()
            }

            /// Convert a big-endian representation to this type.
            pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> CtOption<Self> {
                Scalar::from_bytes_be(bytes).map($name)
            }

            /// Hash arbitrary data to this struct
            pub fn map_to_scalar<T>(msg: T, dst: T) -> Result<Self, Error>
            where
            T: AsRef<[u8]>,
            {
                Ok(Self(map_message_to_scalar_as_hash(msg, dst)?))
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
