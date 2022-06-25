use super::constants::{
    MIN_KEY_GEN_IKM_LENGTH,
    OCTET_POINT_G2_LENGTH,
    OCTET_SCALAR_LENGTH,
};
use crate::{
    common::util::vec_to_byte_array,
    curves::bls12_381::{
        generate_sk,
        sk_to_pk_in_g2,
        G2Affine,
        G2Projective,
        Scalar,
    },
    error::Error,
    print_byte_array,
};
use ff::Field;
use group::{Curve, Group};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::Choice;
use zeroize::Zeroize;

/// The secret key is field element 0 < `x` < `r`
/// where `r` is the curve order. See Section 4.3 in
/// <https://eprint.iacr.org/2016/663.pdf>.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretKey(pub Box<Scalar>);

impl Default for SecretKey {
    fn default() -> Self {
        Self(Box::new(Scalar::zero()))
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0 = Box::new(Scalar::zero());
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<&SecretKey> for [u8; SecretKey::SIZE_BYTES] {
    fn from(sk: &SecretKey) -> [u8; SecretKey::SIZE_BYTES] {
        sk.to_bytes()
    }
}

impl SecretKey {
    /// Number of bytes needed to represent the secret key.
    pub const SIZE_BYTES: usize = OCTET_SCALAR_LENGTH;

    /// Computes a secret key from an IKM, as defined by
    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3
    /// Note this procedure does not follow
    /// https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-keygen
    pub fn new<T>(ikm: T, key_info: T) -> Option<Self>
    where
        T: AsRef<[u8]>,
    {
        if let Some(out) = generate_sk(ikm, key_info) {
            return Some(SecretKey(Box::new(out)));
        }
        None
    }

    /// Compute a secret key from a CS-PRNG.
    pub fn random<R, T>(rng: &mut R, key_info: T) -> Option<Self>
    where
        R: RngCore + CryptoRng,
        T: AsRef<[u8]>,
    {
        let mut ikm = [0u8; MIN_KEY_GEN_IKM_LENGTH];

        if rng.try_fill_bytes(&mut ikm).is_ok() {
            return Self::new(ikm.as_ref(), key_info.as_ref());
        }
        None
    }

    pub(super) fn as_scalar(&self) -> Scalar {
        *self.0
    }

    /// Convert a vector of bytes of big-endian representation of the secret
    /// key.
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        match vec_to_byte_array::<{ Self::SIZE_BYTES }>(bytes) {
            Ok(result) => Self::from_bytes(&result),
            Err(e) => Err(e),
        }
    }

    /// Convert the secret key to a big-endian representation.
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        self.0.to_bytes_be()
    }

    /// Convert a big-endian representation of the secret key.
    pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> Result<Self, Error> {
        let result =
            Scalar::from_bytes_be(bytes).map(|s| SecretKey(Box::new(s)));

        if result.is_some().unwrap_u8() == 1u8 {
            Ok(result.unwrap())
        } else {
            Err(Error::BadEncoding)
        }
    }
}

/// A BBS public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(pub(crate) G2Projective);

impl Default for PublicKey {
    fn default() -> Self {
        Self(G2Projective::identity())
    }
}

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey(")?;
        print_byte_array!(f, self.point_to_octets());
        write!(f, ")")
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
    /// Number of bytes needed to represent the public key in compressed form.
    pub const SIZE_BYTES: usize = OCTET_POINT_G2_LENGTH;

    /// Check if the `PublicKey` is valid.
    pub fn is_valid(&self) -> Choice {
        !self.0.is_identity() & self.0.to_affine().is_torsion_free()
    }

    /// Get the G2 representation in affine, compressed and big-endian form
    /// of PublicKey.
    pub fn point_to_octets(&self) -> [u8; Self::SIZE_BYTES] {
        self.0.to_affine().to_compressed()
    }

    /// Convert a vector of bytes of big-endian representation of the public
    /// key.
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
            Err(Error::BadEncoding)
        }
    }
}

/// A BBS key pair.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    /// Secret key.
    pub secret_key: SecretKey,

    /// Public key.
    pub public_key: PublicKey,
}

impl Zeroize for KeyPair {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.zeroize();
        drop(self.public_key);
    }
}

impl KeyPair {
    /// Generate a BBS key pair from provided IKM.
    pub fn new<T>(ikm: T, key_info: T) -> Option<Self>
    where
        T: AsRef<[u8]>,
    {
        if let Some(secret_key) = SecretKey::new(ikm, key_info) {
            return Some(Self {
                secret_key: secret_key.clone(),
                public_key: PublicKey::from(&secret_key),
            });
        }
        None
    }

    /// Compute a secret key from a CS-PRNG.
    pub fn random<R, T>(rng: &mut R, key_info: T) -> Option<Self>
    where
        R: RngCore + CryptoRng,
        T: AsRef<[u8]>,
    {
        let mut ikm = [0u8; MIN_KEY_GEN_IKM_LENGTH];

        if rng.try_fill_bytes(&mut ikm).is_ok() {
            return Self::new(ikm.as_ref(), key_info.as_ref());
        }
        None
    }
}
