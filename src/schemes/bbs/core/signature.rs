#![allow(non_snake_case)]
use super::{
    constants::{g1_affine_compressed_size, scalar_size, XOF_NO_OF_BYTES},
    generator::Generators,
    public_key::PublicKey,
    secret_key::SecretKey,
    types::Message,
    utils::{compute_B, compute_domain},
};
use crate::{
    common::util::vec_to_byte_array,
    curves::bls12_381::{Bls12, G1Affine, G1Projective, G2Projective, Scalar},
    error::Error,
};
use core::{convert::TryFrom, fmt};
use digest::{ExtendableOutput, Update, XofReader};
use ff::Field;
use group::{Curve, Group};
use pairing::Engine;
use serde::{
    de::{Error as DError, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize,
    Deserializer,
    Serialize,
    Serializer,
};
use sha3::Shake256;
use subtle::{Choice, ConditionallySelectable};

/// A BBS+ signature
#[allow(non_snake_case)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Signature {
    pub(crate) A: G1Projective,
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
                Signature::from_bytes(&arr).map_err(|_| {
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
        Self {
            A: G1Projective::identity(),
            e: Scalar::zero(),
            s: Scalar::zero(),
        }
    }
}

impl ConditionallySelectable for Signature {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            A: G1Projective::conditional_select(&a.A, &b.A, choice),
            e: Scalar::conditional_select(&a.e, &b.e, choice),
            s: Scalar::conditional_select(&a.s, &b.s, choice),
        }
    }
}

impl Signature {
    /// The number of bytes in a signature
    pub const SIZE_BYTES: usize =
        g1_affine_compressed_size() + 2 * scalar_size();

    /// Generate a new signature where all messages are known to the signer.
    /// This method follows `Sign` API as defined in BBS Signature spec
    /// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.4>
    pub fn new<T, M>(
        SK: &SecretKey,
        PK: &PublicKey,
        header: T,
        generators: &Generators,
        msgs: M,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        M: AsRef<[Message]>,
    {
        let header = header.as_ref();
        let msgs = msgs.as_ref();

        // Input parameter checks
        // Error out if there is no `header` and also not any `Message`
        if header.is_empty() && msgs.is_empty() {
            return Err(Error::BadParams {
                cause: "nothing to sign".to_owned(),
            });
        }
        // Error out if blinding generators are less than messages
        if generators.message_blinding_points_length() < msgs.len() {
            return Err(Error::CryptoNotEnoughMessageGenerators {
                generators: generators.message_blinding_points_length(),
                messages: msgs.len(),
            });
        }
        if SK.0.is_zero().unwrap_u8() == 1 {
            return Err(Error::CryptoInvalidSecretKey);
        }

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        // TODO include Ciphersuite_ID
        let domain = compute_domain(PK, header, generators);

        // (e, s) = hash_to_scalar((SK  || domain || msg_1 || ... || msg_L), 2)
        let mut hasher = Shake256::default();
        hasher.update(SK.to_bytes());
        hasher.update(domain.to_bytes_be());
        for m in msgs {
            hasher.update(m.to_bytes())
        }
        let mut reader = hasher.finalize_xof();
        let mut res = [0u8; XOF_NO_OF_BYTES];
        reader.read(&mut res);

        // Should yield non-zero values for `e` and `s`, very small likelihood
        // of it being zero
        let e = Scalar::from_bytes_wide(&res);
        let e = if e.is_some().unwrap_u8() == 1u8 {
            e.unwrap()
        } else {
            return Err(Error::CryptoSigning {
                cause: "Failed to generate `a` component of signature"
                    .to_string(),
            });
        };

        reader.read(&mut res);
        let s = Scalar::from_bytes_wide(&res);
        let s = if s.is_some().unwrap_u8() == 1u8 {
            s.unwrap()
        } else {
            return Err(Error::CryptoSigning {
                cause: "Failed to generate `s` component of signature"
                    .to_string(),
            });
        };

        // B = P1 + H_s * s + H_d * domain + H_1 * msg_1 + ... + H_L * msg_L
        let B = compute_B(&s, &domain, msgs, generators);
        let exp = (e + SK.0).invert();
        let exp = if exp.is_some().unwrap_u8() == 1u8 {
            exp.unwrap()
        } else {
            return Err(Error::CryptoSigning {
                cause: "Failed to generate `exp` for `a` component of \
                        signature"
                    .to_string(),
            });
        };

        // A = B * (1 / (SK + e))
        Ok(Self { A: B * exp, e, s })
    }

    /// Verify a signature.
    /// This method follows `Verify` API as defined in BBS Signature spec
    /// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.5>
    pub fn verify<T, M>(
        &self,
        PK: &PublicKey,
        header: T,
        generators: &Generators,
        msgs: M,
    ) -> Result<bool, Error>
    where
        T: AsRef<[u8]>,
        M: AsRef<[Message]>,
    {
        let header = header.as_ref();
        let msgs = msgs.as_ref();

        // Input parameter checks
        // Error out if there is no `header` and also not any `Message`
        if header.is_empty() && msgs.is_empty() {
            return Err(Error::BadParams {
                cause: "nothing to verify".to_owned(),
            });
        }
        // If there are more messages than generators then we cannot verify the
        // signature
        if generators.message_blinding_points_length() < msgs.len() {
            return Err(Error::CryptoNotEnoughMessageGenerators {
                generators: generators.message_blinding_points_length(),
                messages: msgs.len(),
            });
        }

        // Validate the public key; it should not be an identity and should
        // belong to subgroup G2.
        if PK.is_valid().unwrap_u8() == 0 {
            return Err(Error::CryptoInvalidPublicKey);
        }

        let W = PK.0;

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        // TODO include Ciphersuite_ID
        let domain = compute_domain(PK, header, generators);

        // B = P1 + H_s * s + H_d * domain + H_1 * msg_1 + ... + H_L * msg_L
        let B = compute_B(&self.s, &domain, msgs, generators);

        let P2 = G2Projective::identity();
        // C1 = e(A, W + P2 * e)
        let C1 =
            Bls12::pairing(&self.A.to_affine(), &(W + P2 * self.e).to_affine());

        // C2 = e(B, P2)
        let C2 = Bls12::pairing(&B.to_affine(), &P2.to_affine());

        Ok(C1 == C2)
    }

    /// Get the byte representation of this signature
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        let mut bytes = [0u8; Self::SIZE_BYTES];
        bytes[0..48].copy_from_slice(&self.A.to_affine().to_compressed());
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

        Ok(Signature { A: a, e, s })
    }
}

#[test]
fn serialization_test() {
    let mut sig = Signature::default();
    sig.A = G1Projective::generator();
    sig.e = Scalar::one();
    sig.s = Scalar::one() + Scalar::one();

    let sig_clone = Signature::from_bytes(&sig.to_bytes());
    assert_eq!(sig_clone.is_ok(), true);
    let sig2 = sig_clone.unwrap();
    assert_eq!(sig, sig2);
    sig.A = G1Projective::identity();
    sig.conditional_assign(&sig2, Choice::from(1u8));
    assert_eq!(sig, sig2);
}

#[cfg(test)]
mod tests {
    use crate::bbs::core::{
        generator::Generators,
        public_key::PublicKey,
        secret_key::SecretKey,
        types::Message,
    };

    const TEST_KEY_GEN_SEED: &[u8; 32] = b"not_A_random_seed_at_Allllllllll";
    const TEST_KEY_INFO: &[u8; 14] = b"signing-key-01";
    const TEST_MESSAGE_DST: &[u8; 9] = b"app:dst-1";
    const TEST_HEADER: &[u8; 11] = b"header_info";

    use super::Signature;
    #[test]
    fn invalid_signature() {
        let sig = Signature::default();
        let pk = PublicKey::default();
        let sk = SecretKey::default();
        let msgs = [Message::default(), Message::default()];
        let generators = Generators::new(&[], &[], &[], 1);
        assert!(Signature::new(&sk, &pk, &[], &generators, &msgs).is_err());
        assert!(sig.verify(&pk, &[], &generators, &msgs).is_err());
        let generators = Generators::new(&[], &[], &[], 3);
        assert!(sig.verify(&pk, &[], &generators, &msgs).is_err());
        assert!(Signature::new(&sk, &pk, &[], &generators, &msgs).is_err());
    }

    #[test]
    fn nominal_signature_e2e() {
        let msgs = [
            Message::hash("message-1".as_ref(), TEST_MESSAGE_DST.as_ref())
                .unwrap(),
            Message::hash("message-2".as_ref(), TEST_MESSAGE_DST.as_ref())
                .unwrap(),
        ];
        let sk =
            SecretKey::new(TEST_KEY_GEN_SEED.as_ref(), TEST_KEY_INFO.as_ref())
                .expect("secret key generation failed");
        let pk = PublicKey::from(&sk);
        let generators = Generators::new(&[], &[], &[], 2);

        let signature =
            Signature::new(&sk, &pk, TEST_HEADER.as_ref(), &generators, &msgs)
                .unwrap();

        assert_eq!(
            signature
                .verify(&pk, TEST_HEADER.as_ref(), &generators, &msgs)
                .unwrap(),
            true
        );
    }
}
