use crate::{
    bls::ciphersuites::BlsCiphersuiteParameters,
    curves::{
        bls12_381::{Bls12, G2Prepared, G2Projective, OCTET_POINT_G2_LENGTH},
        point_serde::octets_to_point_g2,
    },
    error::Error,
    print_byte_array,
};
use core::fmt;
use ff::Field;
use group::{Curve, Group};
use pairing::{MillerLoopResult, MultiMillerLoop};
use serde::{
    de::{Error as DError, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize,
    Deserializer,
    Serialize,
    Serializer,
};
use subtle::{Choice, ConditionallySelectable};

use super::key_pair::{PublicKey, SecretKey};

/// A BLS signature
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct Signature(G2Projective);

impl core::fmt::Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature(")?;
        print_byte_array!(f, &self.0.to_affine().to_compressed());
        write!(f, ")",)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_octets();
        let mut seq = s.serialize_tuple(bytes.len())?;
        for b in &bytes {
            seq.serialize_element(b)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(d: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor;

        impl<'de> Visitor<'de> for ArrayVisitor {
            type Value = Signature;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "expected byte array")
            }

            #[allow(clippy::needless_range_loop)]
            fn visit_seq<A>(self, mut seq: A) -> Result<Signature, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [0u8; Signature::SIZE_BYTES];
                for i in 0..arr.len() {
                    arr[i] = seq
                        .next_element()?
                        .ok_or_else(|| DError::invalid_length(i, &self))?;
                }
                Signature::from_octets(&arr).map_err(|_| {
                    DError::invalid_value(
                        serde::de::Unexpected::Bytes(&arr),
                        &self,
                    )
                })
            }
        }

        d.deserialize_tuple(Signature::SIZE_BYTES, ArrayVisitor)
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self(G2Projective::identity())
    }
}

impl ConditionallySelectable for Signature {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(G2Projective::conditional_select(&a.0, &b.0, choice))
    }
}

impl Signature {
    /// The number of bytes in a `Signature`.
    pub const SIZE_BYTES: usize = OCTET_POINT_G2_LENGTH;

    /// Generate a new `Signature`.
    pub fn new<T, C>(sk: &SecretKey, message: T) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        C: BlsCiphersuiteParameters<'static>,
    {
        let message = message.as_ref();

        // Input parameter checks
        // Error out if there is no `Messages`
        if message.is_empty() {
            return Err(Error::BadParams {
                cause: "nothing to sign".to_owned(),
            });
        }
        if sk.0.is_zero().unwrap_u8() == 1 {
            return Err(Error::InvalidSecretKey);
        }

        let q = C::hash_to_g2(message, None)?;

        Ok(Self(q * (*sk.0)))
    }

    /// Verify a signature.
    pub fn verify<T, C>(
        &self,
        pk: &PublicKey,
        message: T,
    ) -> Result<bool, Error>
    where
        T: AsRef<[u8]>,
        C: BlsCiphersuiteParameters<'static>,
    {
        let message = message.as_ref();
        // Input parameter checks
        // Error out if there is no `Message`
        if message.is_empty() {
            return Err(Error::BadParams {
                cause: "nothing to verify".to_owned(),
            });
        }
        // Validate the public key; it should not be an identity and should
        // belong to subgroup G2.
        if pk.is_valid().unwrap_u8() == 0 {
            return Err(Error::InvalidPublicKey);
        }
        let xp = pk.0;
        let q = C::hash_to_g2(message, None)?;
        let p = C::p1();

        // C1 = pairing(Q, xP)
        let c1 = (&xp.to_affine(), &G2Prepared::from((q).to_affine()));

        // C2 = pairing(R, -P)
        // -P2, because we use multi_miller_loop
        let c2 = (&(-p.to_affine()), &G2Prepared::from(self.0.to_affine()));

        // C1 == C2
        // multi_miller_loop(C1, C2) == 1
        Ok(Bls12::multi_miller_loop(&[c1, c2])
            .final_exponentiation()
            .is_identity()
            .unwrap_u8()
            == 1u8)
    }

    /// Get the octets representation of `Signature`.
    pub fn to_octets(self) -> [u8; Self::SIZE_BYTES] {
        self.0.to_affine().to_compressed()
    }

    /// Get the `Signature` from a sequence of bytes in big endian
    /// format.
    pub fn from_octets(data: &[u8; Self::SIZE_BYTES]) -> Result<Self, Error> {
        Ok(Self(octets_to_point_g2(&data)?))
    }
}
