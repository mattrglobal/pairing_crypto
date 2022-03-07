use super::util::vec_to_byte_array;
use crate::curves::bls12_381::Scalar;
use hkdf::HkdfExtract;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// The secret key is field element 0 < `x` < `r`
/// where `r` is the curve order. See Section 4.3 in
/// <https://eprint.iacr.org/2016/663.pdf>
#[derive(Clone, Debug, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub Scalar);

impl Default for SecretKey {
    fn default() -> Self {
        Self(Scalar::zero())
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
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let scalar = Scalar::deserialize(d)?;
        Ok(Self(scalar))
    }
}

impl SecretKey {
    /// Number of bytes needed to represent the secret key
    pub const BYTES: usize = 32;

    /// Computes a new secret key either from a supplied seed or random
    pub fn new(salt: &[u8], data: Option<Vec<u8>>) -> Option<Self> {
        match data {
            Some(s) => SecretKey::from_seed(salt, s.to_vec()),
            None => SecretKey::random(salt),
        }
    }

    /// Compute a secret key from seed via an HKDF
    fn from_seed<B: AsRef<[u8]>>(salt: &[u8], data: B) -> Option<Self> {
        generate_secret_key(salt, data.as_ref())
    }

    /// Compute a secret key from a CS-PRNG
    fn random(salt: &[u8]) -> Option<Self> {
        let mut rng = thread_rng();
        let mut data = [0u8; Self::BYTES];
        rng.fill_bytes(&mut data);
        generate_secret_key(salt, &data)
    }

    /// Get the byte representation of this key
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = self.0.to_bytes();
        // Make big endian
        bytes.reverse();
        bytes
    }

    /// Convert a vector of bytes of big-endian representation of the secret key
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, String> {
        match vec_to_byte_array::<{ Self::BYTES }>(bytes) {
            Ok(result) => Self::from_bytes(&result),
            Err(_) => return Err("Secret key length incorrect expected 32 bytes".to_string()),
        }
    }

    /// Convert a big-endian representation of the secret key
    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> Result<Self, String> {
        let mut t = [0u8; Self::BYTES];
        t.copy_from_slice(bytes);
        t.reverse();
        let result = Scalar::from_bytes(&t).map(SecretKey);

        if result.is_some().unwrap_u8() == 1u8 {
            Ok(result.unwrap())
        } else {
            Err("Failed to decompress secret key from bytes".to_string())
        }
    }
}

fn generate_secret_key(salt: &[u8], ikm: &[u8]) -> Option<SecretKey> {
    const INFO: [u8; 2] = [0u8, 48u8];

    let mut extracter = HkdfExtract::<sha2::Sha256>::new(Some(salt));
    extracter.input_ikm(ikm);
    extracter.input_ikm(&[0u8]);
    let (_, h) = extracter.finalize();

    let mut output = [0u8; 48];
    if h.expand(&INFO, &mut output).is_err() {
        None
    } else {
        Some(SecretKey(Scalar::from_okm(&output)))
    }
}

#[test]
fn test_from_seed() {
    let seed = [0u8; 32];
    let sk = SecretKey::from_seed(b"BLS-SIG-KEYGEN-SALT-", seed);
    let expected = [
        4, 86, 144, 246, 168, 251, 111, 172, 156, 231, 193, 23, 23, 64, 228, 226, 225, 245, 114, 3,
        98, 64, 230, 167, 160, 145, 192, 218, 227, 59, 53, 74,
    ];
    assert_eq!(sk.unwrap().0.to_bytes(), expected);
}
