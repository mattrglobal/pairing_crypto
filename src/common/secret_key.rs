use super::{error::Error, util::vec_to_byte_array};
use blstrs::{generate_secret_key, Scalar};
use ff::{Field, PrimeField};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::DefaultIsZeroes;

/// The secret key is field element 0 < `x` < `r`
/// where `r` is the curve order. See Section 4.3 in
/// <https://eprint.iacr.org/2016/663.pdf>
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretKey(pub Scalar);

impl Default for SecretKey {
    fn default() -> Self {
        Self(Scalar::zero())
    }
}

impl DefaultIsZeroes for SecretKey {}

impl From<SecretKey> for [u8; SecretKey::SIZE_BYTES] {
    fn from(sk: SecretKey) -> [u8; SecretKey::SIZE_BYTES] {
        sk.to_bytes()
    }
}

impl<'a> From<&'a SecretKey> for [u8; SecretKey::SIZE_BYTES] {
    fn from(sk: &'a SecretKey) -> [u8; SecretKey::SIZE_BYTES] {
        sk.to_bytes()
    }
}

impl SecretKey {
    /// Number of bytes needed to represent the secret key
    pub const SIZE_BYTES: usize = (Scalar::NUM_BITS as usize + 8 - 1) / 8;

    /// Computes a secret key from an IKM, as defined by
    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3
    /// Note this procedure does not follow
    /// https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-keygen
    pub fn new<T1, T2>(ikm: T1, key_info: T2) -> Option<Self>
    where
        T1: AsRef<[u8]>,
        T2: AsRef<[u8]>,
    {
        if let Some(out) = generate_secret_key(ikm, key_info) {
            return Some(SecretKey(out));
        }
        None
    }

    /// Compute a secret key from a CS-PRNG
    pub fn random<R>(rng: &mut R) -> Option<Self>
    where
        R: RngCore + CryptoRng,
    {
        let mut ikm = [0u8; Self::SIZE_BYTES];

        if rng.try_fill_bytes(&mut ikm).is_ok() {
            let key_info = [];

            return Self::new(ikm, key_info);
        }
        None
    }

    /// Convert a vector of bytes of big-endian representation of the secret key
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        match vec_to_byte_array::<{ Self::SIZE_BYTES }>(bytes) {
            Ok(result) => Self::from_bytes(&result),
            Err(e) => Err(e),
        }
    }

    /// Convert the secret key to a big-endian representation
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        self.0.to_bytes_be()
    }

    /// Convert a big-endian representation of the secret key
    pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> Result<Self, Error> {
        let result = Scalar::from_bytes_be(bytes).map(SecretKey);

        if result.is_some().unwrap_u8() == 1u8 {
            Ok(result.unwrap())
        } else {
            Err(Error::CryptoBadEncoding)
        }
    }
}

#[test]
fn test_from_seed() {
    pub const MIN_IKM_LENGTH_BYTES: usize = 32;

    let seed = [0u8; MIN_IKM_LENGTH_BYTES];
    let key_info = [];

    let sk = SecretKey::new(seed, key_info);
    let expected = [
        77, 18, 154, 25, 223, 134, 160, 245, 52, 91, 173, 76, 198, 242, 73,
        236, 42, 129, 156, 204, 51, 134, 137, 91, 235, 79, 125, 152, 179, 219,
        98, 53,
    ];
    assert_eq!(sk.unwrap().to_bytes(), expected);
}
