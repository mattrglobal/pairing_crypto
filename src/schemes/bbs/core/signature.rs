#![allow(non_snake_case)]
use super::{
    generator::Generators,
    key_pair::{PublicKey, SecretKey},
    types::{Message, SignatureTrace},
    utils::{compute_B, compute_domain},
};
use crate::{
    bbs::ciphersuites::BbsCiphersuiteParameters,
    common::util::print_byte_array,
    curves::{
        bls12_381::{
            Bls12,
            G1Projective,
            G2Prepared,
            Scalar,
            OCTET_POINT_G1_LENGTH,
            OCTET_SCALAR_LENGTH,
        },
        point_serde::{octets_to_point_g1, point_to_octets_g1},
    },
    error::Error,
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

use crate::bls::core::key_pair::PublicKey as BlsPublicKey;

/// A BBS+ signature
#[allow(non_snake_case)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct Signature {
    pub(crate) A: G1Projective,
    pub(crate) e: Scalar,
}

impl core::fmt::Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature(A: ")?;
        print_byte_array!(f, point_to_octets_g1(&self.A));
        write!(f, ", e: {})", self.e)
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
        }
    }
}

impl ConditionallySelectable for Signature {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            A: G1Projective::conditional_select(&a.A, &b.A, choice),
            e: Scalar::conditional_select(&a.e, &b.e, choice),
        }
    }
}

impl Signature {
    /// The number of bytes in a `Signature`.
    pub const SIZE_BYTES: usize = OCTET_POINT_G1_LENGTH + OCTET_SCALAR_LENGTH;

    const G1_COMPRESSED_SIZE: usize = OCTET_POINT_G1_LENGTH;
    const SCALAR_SIZE: usize = OCTET_SCALAR_LENGTH;

    /// Generate a new `Signature` where all messages are known to the signer.
    /// This method follows `Sign` API as defined in BBS Signature spec
    /// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.4>
    /// Security Warning: `SK` and `PK` paramters must be related key-pair
    /// generated using `KeyPair` APIs.

    pub fn new<T, M, G, C>(
        SK: &SecretKey,
        PK: &PublicKey,
        header: Option<T>,
        generators: &G,
        messages: M,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        M: AsRef<[Message]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        Self::new_private_with_trace::<T, M, G, C>(
            SK, PK, header, generators, messages, None,
        )
    }

    #[cfg(feature = "__private_bbs_fixtures_generator_api")]
    pub fn new_with_trace<T, M, G, C>(
        SK: &SecretKey,
        PK: &PublicKey,
        header: Option<T>,
        generators: &G,
        messages: M,
        trace: Option<&mut SignatureTrace>,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        M: AsRef<[Message]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        Self::new_private_with_trace::<T, M, G, C>(
            SK, PK, header, generators, messages, trace,
        )
    }

    fn new_private_with_trace<T, M, G, C>(
        SK: &SecretKey,
        PK: &PublicKey,
        header: Option<T>,
        generators: &G,
        messages: M,
        mut trace: Option<&mut SignatureTrace>,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        M: AsRef<[Message]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
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
            compute_domain::<_, _, C>(PK, header, messages.len(), generators)?;

        // e_s_octs = serialize((SK, domain, msg_1, ..., msg_L))
        let mut data_to_hash = vec![];
        data_to_hash.extend(SK.to_bytes().as_ref());
        data_to_hash.extend(domain.to_bytes_be().as_ref());
        for m in messages {
            data_to_hash.extend(m.to_bytes().as_ref());
        }

        // if e_s_octs is INVALID, return INVALID
        // e_s_expand = expand_message(e_s_octs, expand_dst, expand_len * 2)
        // if e_s_expand is INVALID, return INVALID
        // e = hash_to_scalar(e_s_expand[0..(expand_len - 1)])
        // s = hash_to_scalar(e_s_expand[expand_len..(expand_len * 2 - 1)])
        let e = C::hash_to_e(&data_to_hash)?;

        // B = P1 + Q * domain + H_1 * msg_1 + ... + H_L * msg_L
        let message_scalars: Vec<Scalar> =
            messages.iter().map(|m| m.0).collect();
        let B = compute_B::<_, C>(&domain, &message_scalars, generators)?;
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

        // Add to the trace when creating the signature fixtures
        if cfg!(feature = "__private_bbs_fixtures_generator_api") {
            if let Some(t) = trace.as_mut() {
                t.B = point_to_octets_g1(&B);
                t.domain = domain.to_bytes_be();
            }
        }

        // A = B * (1 / (SK + e))
        Ok(Self { A: B * exp, e })
    }

    /// Generate a bound bbs signature.
    pub fn new_bound<T, M, G, C>(
        SK: &SecretKey,
        PK: &PublicKey,
        BlsPk: &BlsPublicKey,
        header: Option<T>,
        generators: &G,
        messages: M,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        M: AsRef<[Message]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
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
        if messages.len() != (generators.message_generators_length() - 1) {
            return Err(Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: messages.len(),
            });
        }
        if SK.0.is_zero().unwrap_u8() == 1 {
            return Err(Error::InvalidSecretKey);
        }

        // domain=hash_to_scalar((PK||L||generators||BP_1||Ciphersuite_ID||header),1)
        let domain = compute_domain::<_, _, C>(
            PK,
            header,
            messages.len() + 1,
            generators,
        )?;

        // (e, s) = hash_to_scalar((SK||BlsPk||domain||msg_1||...||msg_L), 2)
        let mut data_to_hash = vec![];
        data_to_hash.extend(SK.to_bytes().as_ref());
        data_to_hash.extend(BlsPk.to_octets().as_ref());
        data_to_hash.extend(domain.to_bytes_be().as_ref());
        for m in messages {
            data_to_hash.extend(m.to_bytes().as_ref());
        }

        let e = C::hash_to_e(&data_to_hash)?;

        // B = P1 + Q*domain + H_1*msg_1 + ... + H_L*msg_L + BlsPk
        let mut points: Vec<_> = vec![C::p1()?, generators.Q()];
        points.extend(generators.message_generators_iter());
        points.remove(1 + generators.message_generators_length());
        let mut scalars: Vec<_> = [Scalar::one(), domain]
            .iter()
            .copied()
            .chain(messages.iter().map(|c| c.0))
            .collect();

        points.push(BlsPk.0);
        scalars.push(Scalar::one());
        let B = G1Projective::multi_exp(&points, &scalars);

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
        Ok(Self { A: B * exp, e })
    }

    /// Verify a signature.
    /// This method follows `Verify` API as defined in BBS Signature spec
    /// <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.5>
    pub fn verify<T, M, G, C>(
        &self,
        PK: &PublicKey,
        header: Option<T>,
        generators: &G,
        messages: M,
    ) -> Result<bool, Error>
    where
        T: AsRef<[u8]>,
        M: AsRef<[Message]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
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
            compute_domain::<_, _, C>(PK, header, messages.len(), generators)?;

        // B = P1 + Q * domain + H_1 * msg_1 + ... + H_L * msg_L
        let message_scalars: Vec<Scalar> =
            messages.iter().map(|m| m.0).collect();
        let B = compute_B::<_, C>(&domain, &message_scalars, generators)?;

        let P2 = C::p2();
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

        // return (a_octets || e_octets)
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

        Ok(Signature { A, e })
    }
}
