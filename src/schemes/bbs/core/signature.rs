use super::{
    g1_affine_compressed_size, scalar_size, Message, MessageGenerators,
    PublicKey, SecretKey,
};
use crate::curves::bls12_381::{
    Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar,
};
use crate::{common::util::vec_to_byte_array, error::Error};
use core::convert::TryFrom;
use core::fmt;
use core::ops::Neg;
use digest::{ExtendableOutput, Update, XofReader};
use ff::Field;
use group::prime::PrimeCurveAffine;
use group::{Curve, Group};
use pairing::{MillerLoopResult as _, MultiMillerLoop};
use serde::{
    de::{Error as DError, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha3::Shake256;
use subtle::{Choice, ConditionallySelectable};

/// A BBS+ signature
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Signature {
    pub(crate) a: G1Projective,
    pub(crate) e: Scalar,
    pub(crate) s: Scalar,
}

impl Serialize for Signature {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_bytes();
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
                let res = Signature::from_bytes(&arr);
                if res.is_ok() {
                    Ok(res.unwrap())
                } else {
                    Err(DError::invalid_value(
                        serde::de::Unexpected::Bytes(&arr),
                        &self,
                    ))
                }
            }
        }

        d.deserialize_tuple(Signature::SIZE_BYTES, ArrayVisitor)
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            a: G1Projective::identity(),
            e: Scalar::zero(),
            s: Scalar::zero(),
        }
    }
}

impl ConditionallySelectable for Signature {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            a: G1Projective::conditional_select(&a.a, &b.a, choice),
            e: Scalar::conditional_select(&a.e, &b.e, choice),
            s: Scalar::conditional_select(&a.s, &b.s, choice),
        }
    }
}

impl Signature {
    /// The number of bytes in a signature
    pub const SIZE_BYTES: usize =
        g1_affine_compressed_size() + 2 * scalar_size();

    /// Generate a new signature where all messages are known to the signer
    pub fn new<M>(
        sk: &SecretKey,
        generators: &MessageGenerators,
        msgs: M,
    ) -> Result<Self, Error>
    where
        M: AsRef<[Message]>,
    {
        let msgs = msgs.as_ref();
        if generators.len() < msgs.len() {
            return Err(Error::CryptoNotEnoughMessageGenerators {
                generators: generators.len(),
                messages: msgs.len(),
            });
        }
        if sk.0.is_zero().unwrap_u8() == 1 {
            return Err(Error::CryptoInvalidSecretKey);
        }

        let mut hasher = Shake256::default();
        hasher.update(&sk.to_bytes());
        hasher.update(generators.h0.to_affine().to_uncompressed());
        for i in 0..generators.len() {
            hasher.update(generators.get(i).to_affine().to_uncompressed());
        }
        for m in msgs {
            hasher.update(m.to_bytes())
        }
        let mut res = [0u8; 64];
        let mut reader = hasher.finalize_xof();
        reader.read(&mut res);

        // Should yield non-zero values for `e` and `s`, very small likelihood of it being zero
        let e = Scalar::from_bytes_wide(&res).unwrap();
        reader.read(&mut res);
        let s = Scalar::from_bytes_wide(&res).unwrap();
        let b = Self::compute_b(s, msgs, generators);
        let exp = (e + sk.0).invert().unwrap();

        Ok(Self { a: b * exp, e, s })
    }

    /// Verify a signature
    pub fn verify<M>(
        &self,
        pk: &PublicKey,
        generators: &MessageGenerators,
        msgs: M,
    ) -> bool
    where
        M: AsRef<[Message]>,
    {
        let msgs = msgs.as_ref();
        // If there are more messages then generators then we cannot verify the signature return false
        if generators.len() < msgs.len() {
            return false;
        }
        // Identity point will always return true which is not what we want
        if pk.0.is_identity().unwrap_u8() == 1 {
            return false;
        }

        let a = G2Projective::generator() * self.e + pk.0;
        let b = Self::compute_b(self.s, msgs, generators).neg();

        Bls12::multi_miller_loop(&[
            (&self.a.to_affine(), &G2Prepared::from(a.to_affine())),
            (&b.to_affine(), &G2Prepared::from(G2Affine::generator())),
        ])
        .final_exponentiation()
        .is_identity()
        .unwrap_u8()
            == 1
    }

    /// Get the byte representation of this signature
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        let mut bytes = [0u8; Self::SIZE_BYTES];
        bytes[0..48].copy_from_slice(&self.a.to_affine().to_compressed());
        let mut e = self.e.to_bytes_be();
        e.reverse();
        bytes[48..80].copy_from_slice(&e[..]);
        let mut s = self.s.to_bytes_be();
        s.reverse();
        bytes[80..112].copy_from_slice(&s[..]);
        bytes
    }

    /// Convert a vector of bytes of big-endian representation of the public key
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        match vec_to_byte_array::<{ Self::SIZE_BYTES }>(bytes) {
            Ok(result) => Self::from_bytes(&result),
            Err(e) => Err(e),
        }
    }

    /// Convert a byte sequence into a signature
    pub fn from_bytes(data: &[u8; Self::SIZE_BYTES]) -> Result<Self, Error> {
        let a_res = G1Affine::from_compressed(
            &<[u8; 48]>::try_from(&data[0..48]).unwrap(),
        )
        .map(G1Projective::from);
        let mut e_bytes = <[u8; 32]>::try_from(&data[48..80]).unwrap();
        e_bytes.reverse();
        let e_res = Scalar::from_bytes_be(&e_bytes);
        let mut s_bytes = <[u8; 32]>::try_from(&data[80..112]).unwrap();
        s_bytes.reverse();
        let s_res = Scalar::from_bytes_be(&s_bytes);

        let a = if a_res.is_some().unwrap_u8() == 1u8 {
            a_res.unwrap()
        } else {
            return Err(Error::CryptoMalformedSignature {
                cause: "Failed to decompress `a` component of signature"
                    .to_string(),
            });
        };

        let e = if e_res.is_some().unwrap_u8() == 1u8 {
            e_res.unwrap()
        } else {
            return Err(Error::CryptoMalformedSignature {
                cause: "Failed to decompress `e` component of signature"
                    .to_string(),
            });
        };

        let s = if s_res.is_some().unwrap_u8() == 1u8 {
            s_res.unwrap()
        } else {
            return Err(Error::CryptoMalformedSignature {
                cause: "Failed to decompress `s` component of signature"
                    .to_string(),
            });
        };

        Ok(Signature { a, e, s })
    }

    /// computes g1 + s * h0 + msgs[0] * h[0] + msgs[1] * h[1] ...
    pub(crate) fn compute_b(
        s: Scalar,
        msgs: &[Message],
        generators: &MessageGenerators,
    ) -> G1Projective {
        let points: Vec<_> = [G1Projective::generator(), generators.h0]
            .iter()
            .copied()
            .chain(generators.iter())
            .collect();
        let scalars: Vec<_> = [Scalar::one(), s]
            .iter()
            .copied()
            .chain(msgs.iter().map(|c| c.0))
            .collect();

        G1Projective::multi_exp(&points, &scalars)
    }
}

#[test]
fn serialization_test() {
    let mut sig = Signature::default();
    sig.a = G1Projective::generator();
    sig.e = Scalar::one();
    sig.s = Scalar::one() + Scalar::one();

    let sig_clone = Signature::from_bytes(&sig.to_bytes());
    assert_eq!(sig_clone.is_ok(), true);
    let sig2 = sig_clone.unwrap();
    assert_eq!(sig, sig2);
    sig.a = G1Projective::identity();
    sig.conditional_assign(&sig2, Choice::from(1u8));
    assert_eq!(sig, sig2);
}

#[test]
fn invalid_signature() {
    let sig = Signature::default();
    let pk = PublicKey::default();
    let sk = SecretKey::default();
    let msgs = [Message::default(), Message::default()];
    let generators = MessageGenerators::from_public_key(pk, 1);
    assert!(Signature::new(&sk, &generators, &msgs).is_err());
    assert_eq!(sig.verify(&pk, &generators, &msgs), false);
    let generators = MessageGenerators::from_public_key(pk, 3);
    assert_eq!(sig.verify(&pk, &generators, &msgs), false);
    assert!(Signature::new(&sk, &generators, &msgs).is_err());
}
