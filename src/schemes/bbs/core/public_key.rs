use super::constants::g2_affine_compressed_size;
use super::secret_key::SecretKey;
use crate::common::util::vec_to_byte_array;
use crate::curves::bls12_381::{sk_to_pk_in_g2, G2Affine, G2Projective};
use crate::error::Error;
use core::ops::{BitOr, Not};
use group::Curve;
use group::Group;
use serde::{Deserialize, Serialize};
use subtle::Choice;

/// A BBS public key
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(pub(crate) G2Projective);

impl Default for PublicKey {
    fn default() -> Self {
        Self(G2Projective::identity())
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(s: &SecretKey) -> Self {
        Self(sk_to_pk_in_g2(&s.0))
    }
}

impl From<PublicKey> for [u8; PublicKey::SIZE_BYTES] {
    fn from(pk: PublicKey) -> Self {
        pk.to_bytes()
    }
}

impl<'a> From<&'a PublicKey> for [u8; PublicKey::SIZE_BYTES] {
    fn from(pk: &'a PublicKey) -> [u8; PublicKey::SIZE_BYTES] {
        pk.to_bytes()
    }
}

impl PublicKey {
    /// Number of bytes needed to represent the public key in compressed form
    pub const SIZE_BYTES: usize = g2_affine_compressed_size();

    /// Check if this signature is valid
    pub fn is_valid(&self) -> Choice {
        self.0.is_identity().not().bitor(self.0.is_on_curve())
    }

    /// Check if this signature is invalid
    pub fn is_invalid(&self) -> Choice {
        self.0.is_identity().bitor(self.0.is_on_curve().not())
    }

    /// Get the byte representation of this key
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        self.0.to_affine().to_compressed()
    }

    /// Convert a vector of bytes of big-endian representation of the public key
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        match vec_to_byte_array::<{ Self::SIZE_BYTES }>(bytes) {
            Ok(result) => Self::from_bytes(&result),
            Err(e) => Err(e),
        }
    }

    /// Convert a big-endian representation of the public key
    pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> Result<Self, Error> {
        let result = G2Affine::from_compressed(bytes)
            .map(|p| Self(G2Projective::from(&p)));

        if result.is_some().unwrap_u8() == 1u8 {
            Ok(result.unwrap())
        } else {
            Err(Error::CryptoBadEncoding)
        }
    }
}
