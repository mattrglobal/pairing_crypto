use blst_lib::{
    blst_bendian_from_scalar, blst_scalar, blst_scalar_from_bendian,
    blst_sk_check,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use super::{error::Error, util::vec_to_byte_array};

/// The secret key is field element 0 < `x` < `r`
/// where `r` is the curve order. See Section 4.3 in
/// <https://eprint.iacr.org/2016/663.pdf>
#[derive(Clone, Debug, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub(crate) blst_scalar);

impl Default for SecretKey {
    fn default() -> Self {
        Self(blst_scalar::default())
    }
}

impl From<SecretKey> for [u8; SecretKey::BYTES] {
    fn from(sk: SecretKey) -> [u8; SecretKey::BYTES] {
        sk.to_bytes()
    }
}

impl<'a> From<&'a SecretKey> for [u8; SecretKey::BYTES] {
    fn from(sk: &'a SecretKey) -> [u8; SecretKey::BYTES] {
        sk.to_bytes()
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bytes().serialize(s)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = SecretKey;

            fn expecting(
                &self,
                formatter: &mut ::core::fmt::Formatter<'_>,
            ) -> ::core::fmt::Result {
                formatter.write_str("a valid byte string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<SecretKey, E>
            where
                E: serde::de::Error,
            {
                if v.len() == SecretKey::BYTES {
                    SecretKey::from_bytes(v).map_err(|_error| {
                        serde::de::Error::custom("decompression failed")
                    })
                } else {
                    Err(serde::de::Error::invalid_length(v.len(), &self))
                }
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}

impl SecretKey {
    /// Number of bytes needed to represent the secret key
    pub const BYTES: usize = 32;

    /// Computes a new secret key either from a supplied seed or random
    pub fn new<T: AsRef<[u8]>>(seed: T, key_info: T) -> Option<Self> {
        Self::from_seed(seed, key_info)
    }

    /// Computes a secret key from an IKM, as defined by 
    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3
    /// Note this procedure does not follow
    /// https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-keygen
    fn from_seed<T: AsRef<[u8]>>(seed: T, key_info: T) -> Option<Self> {
        generate_secret_key(seed, key_info).ok()
    }

    /// Compute a secret key from a CS-PRNG
    pub fn random<R>(rng: &mut R) -> Option<Self>
    where
        R: RngCore + CryptoRng,
    {
        let mut seed = [0u8; Self::BYTES];
        rng.try_fill_bytes(&mut seed)
            .expect("failed to draw bytes from random number generator");

        let key_info = [0u8; Self::BYTES];

        Self::from_seed(seed, key_info)
    }

    /// Convert a vector of bytes of big-endian representation of the secret key
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        match vec_to_byte_array::<{ Self::BYTES }>(bytes) {
            Ok(result) => Self::from_bytes(&result),
            Err(_) => return Err(Error::Conversion),
        }
    }

    // serialize
    fn serialize(&self) -> [u8; 32] {
        let mut sk_out = [0; 32];
        unsafe {
            blst_bendian_from_scalar(sk_out.as_mut_ptr(), &self.0);
        }
        sk_out
    }

    // deserialize
    fn deserialize(sk_in: &[u8]) -> Result<Self, Error> {
        let mut sk = blst_scalar::default();
        if sk_in.len() != 32 {
            return Err(Error::CryptoBadEncoding);
        }
        unsafe {
            blst_scalar_from_bendian(&mut sk, sk_in.as_ptr());
            if !blst_sk_check(&sk) {
                return Err(Error::CryptoBadEncoding);
            }
        }
        Ok(Self(sk))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        SecretKey::serialize(&self)
    }

    pub fn from_bytes(sk_in: &[u8]) -> Result<Self, Error> {
        SecretKey::deserialize(sk_in)
    }
}

    /// Computes a secret key from an IKM, as defined by 
    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3
    /// Note this procedure does not follow
    /// https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-keygen
fn generate_secret_key<T: AsRef<[u8]>>(
    ikm: T,
    key_info: T,
) -> Result<SecretKey, Error> {
    let ikm = ikm.as_ref();
    if ikm.len() < SecretKey::BYTES {
        return Err(Error::CryptoInvalidIkmLength);
    }

    let key_info = key_info.as_ref();
    let mut out = blst_lib::blst_scalar::default();
    unsafe {
        blst_lib::blst_keygen(
            &mut out,
            ikm.as_ptr(),
            ikm.len(),
            key_info.as_ptr(),
            key_info.len(),
        )
    };

    Ok(SecretKey(out))
}

#[test]
fn test_from_seed() {
    let seed = [0u8; 32];
    let key_info = [0u8; 32];

    let sk = SecretKey::new(seed, key_info);
    let expected = [
        25, 226, 206, 49, 243, 163, 5, 65, 109, 59, 93, 241, 131, 89, 233, 208,
        89, 145, 234, 225, 7, 19, 70, 193, 238, 78, 164, 52, 85, 176, 39, 119,
    ];
    assert_eq!(sk.unwrap().to_bytes(), expected);
}
