use crate::curves::bls12_381::Scalar;
use digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::convert::TryFrom;
use subtle::CtOption;

/// Convert slice to a fixed array
macro_rules! slicer {
    ($d:expr, $b:expr, $e:expr, $s:expr) => {
        &<[u8; $s]>::try_from(&$d[$b..$e]).unwrap()
    };
}

macro_rules! scalar_wrapper {
    ($(#[$docs:meta])*
     $name:ident) => {
        use super::*;
        use crate::curves::bls12_381::Scalar;
        use serde::{Deserialize, Serialize};
        use subtle::CtOption;

        $(#[$docs])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize, Serialize)]
        pub struct $name(pub Scalar);

        impl Default for $name {
            fn default() -> Self {
                Self(Scalar::zero())
            }
        }

        impl $name {
            /// The number of bytes needed to represent this struct
            pub const BYTES: usize = 32;

            /// Hash arbitrary data to this struct
            pub fn hash<B: AsRef<[u8]>>(data: B) -> Self {
                Self(super::hash_to_scalar(data))
            }

            /// Generate a random struct
            pub fn random(rng: impl rand_core::RngCore) -> Self {
                use ff::Field;
                Self(Scalar::random(rng))
            }

            /// Get the byte sequence that represents this struct
            pub fn to_bytes(&self) -> [u8; Self::BYTES] {
                super::scalar_to_bytes(self.0)
            }

            /// Convert a big-endian representation of the struct
            pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
                super::scalar_from_bytes(bytes).map(Self)
            }

            /// Convert a 48 byte digest into a struct
            pub fn from_okm(bytes: &[u8; super::COMMITMENT_G1_BYTES]) -> Self {
                Self(Scalar::from_okm(bytes))
            }
        }
    };
}

/// Hashes a byte sequence to a Scalar
pub fn hash_to_scalar<B: AsRef<[u8]>>(data: B) -> Scalar {
    const BYTES: usize = 48;
    let mut res = [0u8; BYTES];
    let mut hasher = Shake256::default();
    hasher.update(data.as_ref());
    let mut reader = hasher.finalize_xof();
    reader.read(&mut res);
    Scalar::from_okm(&res)
}

/// Converts a scalar to big endian bytes
pub fn scalar_to_bytes(s: Scalar) -> [u8; 32] {
    let mut bytes = s.to_bytes();
    // Make big endian
    bytes.reverse();
    bytes
}

/// Convert a big endian byte sequence to a Scalar
pub fn scalar_from_bytes(bytes: &[u8; 32]) -> CtOption<Scalar> {
    let mut t = [0u8; 32];
    t.copy_from_slice(bytes);
    t.reverse();
    Scalar::from_bytes(&t)
}

/// Convert a vector of bytes to a fixed length byte array
pub fn vec_to_byte_array<const N: usize>(vec: Vec<u8>) -> Result<[u8; N], String> {
    match <[u8; N]>::try_from(vec) {
        Ok(result) => Ok(result),
        // TODO specify mismatch in length?
        Err(_) => Err("Input data length incorrect".to_string()),
    }
}
