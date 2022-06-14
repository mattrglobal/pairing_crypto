use super::{
    constants::{OCTET_POINT_G2_LENGTH},
    secret_key::SecretKey,
};
use crate::{
    common::util::vec_to_byte_array,
    curves::bls12_381::{sk_to_pk_in_g2, G2Affine, G2Projective},
    error::Error,
};
use core::ops::{BitOr, Not};
use group::{Curve, Group};
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
        pk.point_to_octets()
    }
}

impl<'a> From<&'a PublicKey> for [u8; PublicKey::SIZE_BYTES] {
    fn from(pk: &'a PublicKey) -> [u8; PublicKey::SIZE_BYTES] {
        pk.point_to_octets()
    }
}

impl PublicKey {
    /// Number of bytes needed to represent the public key in compressed form
    pub const SIZE_BYTES: usize = OCTET_POINT_G2_LENGTH;

    /// Check if this PublicKey is valid
    pub fn is_valid(&self) -> Choice {
        self.0
            .is_identity()
            .not()
            .bitor(self.0.to_affine().is_torsion_free())
    }

    /// Get the G2 representation in affine, compressed and big-endian form
    /// of PublicKey.
    pub fn point_to_octets(&self) -> [u8; Self::SIZE_BYTES] {
        self.0.to_affine().to_compressed()
    }

    /// Convert a vector of bytes of big-endian representation of the public key
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        match vec_to_byte_array::<{ Self::SIZE_BYTES }>(bytes) {
            Ok(result) => Self::octets_to_point(&result),
            Err(e) => Err(e),
        }
    }

    /// Convert from G2 point in affine, compressed and big-endian form to
    /// PublicKey.
    pub fn octets_to_point(
        bytes: &[u8; Self::SIZE_BYTES],
    ) -> Result<Self, Error> {
        let result = G2Affine::from_compressed(bytes)
            .map(|p| Self(G2Projective::from(&p)));

        if result.is_some().unwrap_u8() == 1u8 {
            Ok(result.unwrap())
        } else {
            Err(Error::CryptoBadEncoding)
        }
    }
}
