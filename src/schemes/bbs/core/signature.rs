#![allow(non_snake_case)]
use super::{
    constants::{OCTET_POINT_G1_LENGTH, OCTET_SCALAR_LENGTH},
    generator::Generators,
    hash_utils::hash_to_scalar,
    key_pair::{PublicKey, SecretKey},
    types::Message,
    utils::{
        compute_B,
        compute_domain,
        octets_to_point_g1,
        point_to_octets_g1,
    },
};
use crate::{
    curves::bls12_381::{
        hash_to_curve::ExpandMessage,
        Bls12,
        G1Projective,
        G2Prepared,
        G2Projective,
        Scalar,
    },
    error::Error,
    print_byte_array,
};
use core::{convert::TryFrom, fmt};
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

/// A BBS+ signature
#[allow(non_snake_case)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct Signature {
    pub(crate) A: G1Projective,
    pub(crate) e: Scalar,
    pub(crate) s: Scalar,
}

impl core::fmt::Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature(A: ")?;
        print_byte_array!(f, point_to_octets_g1(&self.A));
        write!(f, ", e: {}, s: {})", self.e, self.s)
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
    /// The number of bytes in a `Signature`.
    pub const SIZE_BYTES: usize =
        OCTET_POINT_G1_LENGTH + 2 * OCTET_SCALAR_LENGTH;

    const G1_COMPRESSED_SIZE: usize = OCTET_POINT_G1_LENGTH;
    const SCALAR_SIZE: usize = OCTET_SCALAR_LENGTH;

    /// Generate a new `Signature` where all messages are known to the signer.
    /// This method follows `Sign` API as defined in BBS Signature spec
    /// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.4>
    /// Security Warning: `SK` and `PK` paramters must be related key-pair
    /// generated using `KeyPair` APIs.
    pub fn new<T, M, X>(
        SK: &SecretKey,
        PK: &PublicKey,
        header: Option<T>,
        generators: &Generators,
        messages: M,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        M: AsRef<[Message]>,
        X: ExpandMessage, 
    {
        let header = header.as_ref();
        let messages = messages.as_ref();

        // Input parameter checks
        // Error out if there is no `header` and also not any `Messages`
        if header.is_none() && messages.is_empty() {
            return Err(Error::BadParams {
                cause: "nothing to sign".to_owned(),
            });
        }
        // Error out if length of messages and generators are not equal
        if messages.len() != generators.message_generators_length() {
            return Err(Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: messages.len(),
            });
        }
        if SK.0.is_zero().unwrap_u8() == 1 {
            return Err(Error::InvalidSecretKey);
        }

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        let domain =
            compute_domain::<_, X>(PK, header, messages.len(), generators)?;

        // (e, s) = hash_to_scalar((SK  || domain || msg_1 || ... || msg_L), 2)
        let mut data_to_hash = vec![];
        data_to_hash.extend(SK.clone().to_bytes().as_ref());
        data_to_hash.extend(domain.to_bytes_be().as_ref());
        for m in messages {
            data_to_hash.extend(m.to_bytes().as_ref());
        }
        let scalars = hash_to_scalar::<X>(&data_to_hash, 2)?;
        let (e, s) = (scalars[0], scalars[1]);

        // B = P1 + H_s * s + H_d * domain + H_1 * msg_1 + ... + H_L * msg_L
        let B = compute_B(&s, &domain, messages, generators)?;
        let exp = (e + SK.as_scalar()).invert();
        let exp = if exp.is_some().unwrap_u8() == 1u8 {
            exp.unwrap()
        } else {
            return Err(Error::CryptoOps {
                cause: "failed to generate `exp` for `A` component of \
                        signature"
                    .to_owned(),
            });
        };

        // A = B * (1 / (SK + e))
        Ok(Self { A: B * exp, e, s })
    }

    /// Verify a signature.
    /// This method follows `Verify` API as defined in BBS Signature spec
    /// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.5>
    pub fn verify<T, M, X>(
        &self,
        PK: &PublicKey,
        header: Option<T>,
        generators: &Generators,
        messages: M,
    ) -> Result<bool, Error>
    where
        T: AsRef<[u8]>,
        M: AsRef<[Message]>,
        X: ExpandMessage,
    {
        let messages = messages.as_ref();

        // Input parameter checks
        // Error out if there is no `header` and also not any `Message`
        if header.is_none() && messages.is_empty() {
            return Err(Error::BadParams {
                cause: "nothing to verify".to_owned(),
            });
        }
        // Error out if length of messages and generators are not equal
        if messages.len() != generators.message_generators_length() {
            return Err(Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: messages.len(),
            });
        }

        // Validate the public key; it should not be an identity and should
        // belong to subgroup G2.
        if PK.is_valid().unwrap_u8() == 0 {
            return Err(Error::InvalidPublicKey);
        }
        let W = PK.0;

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        let domain =
            compute_domain::<_, X>(PK, header, messages.len(), generators)?;

        // B = P1 + H_s * s + H_d * domain + H_1 * msg_1 + ... + H_L * msg_L
        let B = compute_B(&self.s, &domain, messages, generators)?;

        let P2 = G2Projective::generator();
        // C1 = (A, W + P2 * e)
        let C1 = (
            &self.A.to_affine(),
            &G2Prepared::from((W + P2 * self.e).to_affine()),
        );

        // C2 = (B, -P2)
        // -P2, because we use multi_miller_loop
        let C2 = (&B.to_affine(), &G2Prepared::from(-P2.to_affine()));

        // C1 == C2
        // multi_miller_loop(C1, C2) == 1
        Ok(Bls12::multi_miller_loop(&[C1, C2])
            .final_exponentiation()
            .is_identity()
            .unwrap_u8()
            == 1u8)
    }

    /// Get the octets representation of `Signature` as defined in BBS spec <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-signaturetooctets>.
    pub fn to_octets(self) -> [u8; Self::SIZE_BYTES] {
        let mut offset = 0;
        let mut end = Self::G1_COMPRESSED_SIZE;
        let mut bytes = [0u8; Self::SIZE_BYTES];

        // A_octets = point_to_octets_g1(A)
        bytes[offset..end].copy_from_slice(&point_to_octets_g1(&self.A));
        offset = end;

        // e_octets = I2OSP(e, octet_scalar_length)
        end += Self::SCALAR_SIZE;
        bytes[offset..end].copy_from_slice(&self.e.to_bytes_be());
        offset = end;

        // s_octets = I2OSP(s, octet_scalar_length)
        bytes[offset..].copy_from_slice(&self.s.to_bytes_be());

        // return (a_octets || e_octets || s_octets)
        bytes
    }

    /// Get the `Signature` from a sequence of bytes in big endian
    /// format. Each member of `Signature` is deserialized from
    /// big-endian bytes as defined in BBS spec <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.11>.
    /// Valid input size is G1_COMPRESSED_SIZE + SCALAR_SIZE * 2
    /// where
    ///      G1_COMPRESSED_SIZE, size of a point in G1 in ompressed form,
    ///      SCALAR_SIZE, size of a `Scalar`
    /// For BLS12-381 based implementation, G1_COMPRESSED_SIZE is 48 byes, and
    /// SCALAR_SIZE is 32 bytes, then bytes sequence will be treated as
    /// [48, 32, 32] to represent (A, e, s).    
    pub fn from_octets(data: &[u8; Self::SIZE_BYTES]) -> Result<Self, Error> {
        let mut offset = 0;
        let mut end = Self::G1_COMPRESSED_SIZE;

        // A = octets_to_point_g1(a_octets)
        // if A is INVALID, return INVALID
        let A = octets_to_point_g1(
            &<[u8; Self::G1_COMPRESSED_SIZE]>::try_from(&data[offset..end])?,
        )?;

        // if A == Identity_G1, return INVALID
        if A.is_identity().unwrap_u8() == 1 {
            return Err(Error::PointIsIdentity);
        }
        offset = end;

        // OS2IP(signature_octets[index..(index + octet_scalar_length - 1)])
        // if e = 0 OR e >= r, return INVALID
        end += Self::SCALAR_SIZE;
        let e = Scalar::from_bytes_be(&<[u8; Self::SCALAR_SIZE]>::try_from(
            &data[offset..end],
        )?);
        if e.is_none().unwrap_u8() == 1u8 {
            return Err(Error::MalformedSignature {
                cause: "failed to deserialize `e` component of signature"
                    .to_owned(),
            });
        };
        let e = e.unwrap();
        if e.is_zero().unwrap_u8() == 1 {
            return Err(Error::UnexpectedZeroValue);
        }
        offset = end;

        // s = OS2IP(signature_octets[index..(index + octet_scalar_length -
        // 1)])
        // if s = 0 OR s >= r, return INVALID
        end += Self::SCALAR_SIZE;
        let s = Scalar::from_bytes_be(&<[u8; Self::SCALAR_SIZE]>::try_from(
            &data[offset..end],
        )?);
        if s.is_none().unwrap_u8() == 1u8 {
            return Err(Error::MalformedSignature {
                cause: "failed to deserialize `s` component of signature"
                    .to_owned(),
            });
        };
        let s = s.unwrap();
        if s.is_zero().unwrap_u8() == 1 {
            return Err(Error::UnexpectedZeroValue);
        }

        Ok(Signature { A, e, s })
    }
}
