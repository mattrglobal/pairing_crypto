use super::{MessageGenerators, Signature};
use crate::curves::bls12_381::{G1Projective, Scalar};
use crate::schemes::bls::SecretKey;
use crate::schemes::core::*;

use digest::{ExtendableOutput, Update, XofReader};
use ff::Field;
use group::Curve;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::Shake256;
use subtle::CtOption;

/// A BBS+ blind signature
/// structurally identical to `Signature` but is used to
/// help with misuse and confusion.
///
/// 1 or more messages have been hidden by the signature recipient
/// so the signer only knows a subset of the messages to be signed
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlindSignature {
    pub(crate) a: G1Projective,
    pub(crate) e: Scalar,
    pub(crate) s: Scalar,
}

impl Serialize for BlindSignature {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let sig = Signature {
            a: self.a,
            e: self.e,
            s: self.s,
        };
        sig.serialize(s)
    }
}

impl<'de> Deserialize<'de> for BlindSignature {
    fn deserialize<D>(d: D) -> Result<BlindSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let sig = Signature::deserialize(d)?;
        Ok(Self {
            a: sig.a,
            e: sig.e,
            s: sig.s,
        })
    }
}

impl BlindSignature {
    /// The number of bytes in a signature
    pub const BYTES: usize = 112;

    /// Generate a blind signature where only a subset of messages are known to the signer
    /// The rest are encoded as a commitment
    pub fn new(
        commitment: Commitment,
        sk: &SecretKey,
        generators: &MessageGenerators,
        msgs: &[(usize, Message)],
    ) -> Result<Self, Error> {
        if generators.len() < msgs.len() {
            return Err(Error::new(1, "not enough message generators"));
        }
        if sk.0.is_zero() {
            return Err(Error::new(2, "invalid secret key"));
        }

        let mut hasher = Shake256::default();
        hasher.update(&sk.to_bytes());
        hasher.update(generators.h0.to_affine().to_uncompressed());
        for i in 0..generators.len() {
            hasher.update(generators.get(i).to_affine().to_uncompressed());
        }
        for (_, m) in msgs.iter() {
            hasher.update(m.to_bytes())
        }
        let mut res = [0u8; 64];
        let mut reader = hasher.finalize_xof();
        reader.read(&mut res);
        // Should yield non-zero values for `e` and `s`, very small likelihood of it being zero
        let e = Scalar::from_bytes_wide(&res);
        reader.read(&mut res);
        let s = Scalar::from_bytes_wide(&res);

        let mut points = Vec::with_capacity(msgs.len() + 3);
        let mut scalars = Vec::with_capacity(msgs.len() + 3);

        points.extend_from_slice(&[commitment.0, G1Projective::generator(), generators.h0]);
        scalars.extend_from_slice(&[Scalar::one(), Scalar::one(), s]);

        for (idx, m) in msgs.iter() {
            points.push(generators.get(*idx));
            scalars.push(m.0);
        }

        let b = G1Projective::sum_of_products(&points[..], &scalars[..]);
        let exp = (e + sk.0).invert().unwrap();

        Ok(Self { a: b * exp, e, s })
    }

    /// Once signature on committed attributes (blind signature) is received, the signature needs to be unblinded.
    /// Takes the blinding factor used in the commitment.
    pub fn to_unblinded(self, blinding: SignatureBlinding) -> Signature {
        Signature {
            a: self.a,
            e: self.e,
            s: self.s + blinding.0,
        }
    }

    /// Get the byte representation of this signature
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let sig = Signature {
            a: self.a,
            e: self.e,
            s: self.s,
        };
        sig.to_bytes()
    }

    /// Convert a byte sequence into a signature
    pub fn from_bytes(data: &[u8; Self::BYTES]) -> CtOption<Self> {
        Signature::from_bytes(data).map(|sig| Self {
            a: sig.a,
            e: sig.e,
            s: sig.s,
        })
    }
}

#[test]
fn serialization_test() {
    let b = BlindSignature {
        a: G1Projective::generator(),
        e: Scalar::one(),
        s: Scalar::one(),
    };

    let bytes = b.to_bytes();
    let b2 = BlindSignature::from_bytes(&bytes);
    assert_eq!(b2.is_some().unwrap_u8(), 1u8);
    assert_eq!(b2.unwrap(), b);
}
