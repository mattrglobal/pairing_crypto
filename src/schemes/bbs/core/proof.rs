#![allow(non_snake_case)]

use super::{
    generator::Generators,
    key_pair::PublicKey,
    signature::Signature,
    types::{Challenge, FiatShamirProof, Message, ProofMessage},
    utils::{compute_B, compute_challenge, compute_domain},
};
use crate::{
    bbs::ciphersuites::BbsCiphersuiteParameters,
    common::util::{create_random_scalar, print_byte_array},
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
use core::convert::TryFrom;
use ff::Field;
use group::{Curve, Group};
use pairing::{MillerLoopResult as _, MultiMillerLoop};
use rand::{CryptoRng, RngCore};
use rand_core::OsRng;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

#[cfg(not(feature = "alloc"))]
use std::collections::BTreeMap;

// Convert slice to a fixed array
macro_rules! slicer {
    ($d:expr, $b:expr, $e:expr, $s:expr) => {
        &<[u8; $s]>::try_from(&$d[$b..$e])?
    };
}

/// The zero-knowledge proof-of-knowledge of a signature that is sent from
/// prover to verifier. Contains the proof of 2 discrete log relations.
/// The `ProofGen` procedure is specified here <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofgen>
/// proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_1, ..., m^_U)), where `U` is
/// number of unrevealed messages.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Proof {
    /// \overline{A}
    pub(crate) A_bar: G1Projective,
    /// \overline{B}
    pub(crate) B_bar: G1Projective,
    /// c
    pub(crate) c: Challenge,
    /// r2^
    pub(crate) r2_hat: FiatShamirProof,
    /// z^
    pub(crate) z_hat: FiatShamirProof,
    /// (m^_1, ..., m^_U)
    pub(crate) m_hat_list: Vec<FiatShamirProof>,
}

impl core::fmt::Display for Proof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Proof(A_bar: ")?;
        print_byte_array!(f, point_to_octets_g1(&self.A_bar));
        write!(f, ", B_bar: ")?;
        print_byte_array!(f, point_to_octets_g1(&self.B_bar));
        write!(
            f,
            ", c: {}, r2^: {}, z^: {}, m^_i: [",
            self.c.0, self.r2_hat.0, self.z_hat.0,
        )?;
        for (i, m_hat) in self.m_hat_list.iter().enumerate() {
            write!(f, "m^_{}: {}, ", i + 1, m_hat.0)?;
        }
        write!(f, "])")
    }
}

impl Proof {
    /// Generates the zero-knowledge proof-of-knowledge of a signature, while
    /// optionally selectively disclosing from the original set of signed messages as defined in `ProofGen` API in BBS Signature specification <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofgen>.
    pub fn new<T, G, C>(
        PK: &PublicKey,
        signature: &Signature,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        messages: &[ProofMessage],
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        Self::new_with_rng::<_, _, _, C>(
            PK, signature, header, ph, generators, messages, OsRng,
        )
    }
    /// Generates the zero-knowledge proof-of-knowledge of a signature, while
    /// optionally selectively disclosing from the original set of signed messages as defined in `ProofGen` API in BBS Signature specification <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofgen> using an externally supplied random number generator.
    pub fn new_with_rng<T, R, G, C>(
        PK: &PublicKey,
        signature: &Signature,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        messages: &[ProofMessage],
        mut rng: R,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        R: RngCore + CryptoRng,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        // Input parameter checks
        // Error out if there is no `header` and not any `ProofMessage`
        if header.is_none() && messages.is_empty() {
            return Err(Error::BadParams {
                cause: "nothing to prove".to_owned(),
            });
        }
        // Error out if length of messages and generators are not equal
        if messages.len() != generators.message_generators_length() {
            return Err(Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_generators_length(),
                messages: messages.len(),
            });
        }

        // The following steps from the `ProofGen` operation defined in https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofgen are implicit in this
        // implementation
        // signature_result = octets_to_signature(signature)
        // (i1, i2,..., iR) = RevealedIndexes
        // (j1, j2,..., jU) = [L] \ RevealedIndexes
        // if signature_result is INVALID, return INVALID
        // (A, e) = signature_result
        // generators =  (Q || || H_1 || ... || H_L)

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        let domain =
            compute_domain::<_, _, C>(PK, header, messages.len(), generators)?;

        // (r1, e~, r2~, r3~, z~) = hash_to_scalar(PRF(8*ceil(log2(r))), 6)
        let r1 = create_random_scalar(&mut rng)?;
        let r2_tilde = create_random_scalar(&mut rng)?;
        let z_tilde = create_random_scalar(&mut rng)?;

        // (m~_j1, ..., m~_jU) =  hash_to_scalar(PRF(8*ceil(log2(r))), U)
        // these random scalars will be generated further below during `C2`
        // computation

        let msg: Vec<_> = messages.iter().map(|m| m.get_message()).collect();

        // Abar = A * r1
        let A_bar = signature.A * r1;

        // B = P1 + Q * domain + H_1 * msg_1 + ... + H_L * msg_L
        let B = compute_B::<_, C>(&domain, msg.as_ref(), generators)?;

        // Bbar = B * r1 - Abar * e
        let B_bar = G1Projective::multi_exp(&[B, A_bar], &[r1, -signature.e]);

        // r2 = r1 ^ -1 mod r
        let r2 = r1.invert();

        if r2.is_none().unwrap_u8() == 1u8 {
            return Err(Error::CryptoOps {
                cause: "Failed to invert `r1`".to_owned(),
            });
        };
        let r2 = r2.unwrap();

        // C = Bbar * r2~ + Abar * z~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
        let mut H_points = Vec::new();
        let mut m_tilde_scalars = Vec::new();
        let mut hidden_messages = Vec::new();
        let mut disclosed_messages = BTreeMap::new();
        for (i, generator) in generators.message_generators_iter().enumerate() {
            match messages[i] {
                ProofMessage::Revealed(m) => {
                    disclosed_messages.insert(i, m);
                }
                ProofMessage::Hidden(m) => {
                    H_points.push(generator);
                    m_tilde_scalars.push(create_random_scalar(&mut rng)?);
                    hidden_messages.push(m.0);
                }
            }
        }

        let C = G1Projective::multi_exp(
            &[[B_bar, A_bar].to_vec(), H_points].concat(),
            &[[r2_tilde, z_tilde].to_vec(), m_tilde_scalars.clone()].concat(),
        );

        // c_array = (A_bar, B_bar, C, R, i1, ..., iR, msg_i1, ..., msg_iR,
        //              domain, ph)
        // c_octs = serialize(c_array)
        // if c_octs is INVALID, return INVALID
        // c = hash_to_scalar(c_octs, 1)
        let c = compute_challenge::<_, C>(
            &A_bar,
            &B_bar,
            &C,
            &disclosed_messages,
            &domain,
            ph,
        )?;

        // r2^ = r2~ + c * r2
        let r2_hat = FiatShamirProof(r2_tilde - c.0 * r2);

        // z^ = z~ + c * e * r2
        let z_hat = FiatShamirProof(z_tilde - c.0 * signature.e * r2);

        // for j in (j1, j2,..., jU): m^_j = m~_j + c * msg_j
        let m_hat_list = m_tilde_scalars
            .iter()
            .zip(hidden_messages.iter())
            .map(|(m_tilde, msg)| {
                let m_hat = *m_tilde + c.0 * (*msg);
                FiatShamirProof(m_hat)
            })
            .collect::<Vec<FiatShamirProof>>();

        Ok(Proof {
            A_bar,
            B_bar,
            c,
            r2_hat,
            z_hat,
            m_hat_list,
        })
    }

    /// Verify the zero-knowledge proof-of-knowledge of a signature with
    /// optionally selectively disclosed messages from the original set of signed messages as defined in `ProofGen` API in BBS Signature specification <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofverify>.
    pub fn verify<T, G, C>(
        &self,
        PK: &PublicKey,
        header: Option<T>,
        ph: Option<T>,
        generators: &mut G,
        disclosed_messages: &BTreeMap<usize, Message>,
        total_no_of_messages: Option<usize>,
    ) -> Result<bool, Error>
    where
        T: AsRef<[u8]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        // If total number of messages is not provided, it defaults to
        // disclosed_messages number + m_hat number
        let total_no_of_messages = total_no_of_messages
            .unwrap_or(self.m_hat_list.len() + disclosed_messages.len());

        // Input parameter checks
        // Error out if there is no `header` and not any `ProofMessage`
        if header.is_none() && (total_no_of_messages == 0) {
            return Err(Error::BadParams {
                cause: "nothing to verify".to_owned(),
            });
        }
        // Check if input proof data commitments matches no. of hidden messages
        if total_no_of_messages != generators.message_generators_length() {
            return Err(Error::BadParams {
                cause: format!(
                    "Incorrect number of messages and generators: \
                     [#generators: {}, #hidden_messages: {}, \
                     #revealed_messages: {}]",
                    generators.message_generators_length(),
                    self.m_hat_list.len(),
                    disclosed_messages.len()
                ),
            });
        }
        if disclosed_messages
            .keys()
            .any(|r| *r >= total_no_of_messages)
        {
            return Err(Error::BadParams {
                cause: format!(
                    "revealed message index value is invalid, maximum allowed \
                     value is {}",
                    total_no_of_messages - 1
                ),
            });
        }
        // if KeyValidate(PK) is INVALID, return INVALID
        // `PK` should not be an identity and should belong to subgroup G2
        if PK.is_valid().unwrap_u8() == 0u8 {
            return Err(Error::InvalidPublicKey);
        }

        // The following steps from the `ProofVerify` operation defined in https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofverify are implicit in this
        // implementation
        // (i1, i2, ..., iR) = RevealedIndexes
        // (j1, j2, ..., jU) = [L]\RevealedIndexes
        // proof_value = octets_to_proof(proof)
        // if proof_value is INVALID, return INVALID
        // (A', Abar, D, c, e^, r2^, z^, (m^_j1,...,m^_jU)) = proof_value
        // generators =  (Q || H_1 || ... || H_L)

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        let domain = compute_domain::<_, _, C>(
            PK,
            header,
            generators.message_generators_length(),
            generators,
        )?;

        // T = P1 + Q * domain + H_i1 * msg_i1 + ... H_iR * msg_iR
        let T_len = 1 + 1 + disclosed_messages.len();
        let mut T_points = Vec::with_capacity(T_len);
        let mut T_scalars = Vec::with_capacity(T_len);
        let P1 = C::p1()?;
        // P1
        T_points.push(P1);
        T_scalars.push(Scalar::one());
        // Q * domain
        T_points.push(generators.Q());
        T_scalars.push(domain);

        let mut C_points_temp = Vec::with_capacity(self.m_hat_list.len());
        let mut C_scalars_temp = Vec::with_capacity(self.m_hat_list.len());
        let mut j = 0;
        for (i, generator) in generators.message_generators_iter().enumerate() {
            if disclosed_messages.contains_key(&i) {
                T_points.push(generator);
                // unwrap() is safe here since we already have checked for
                // existence of key
                T_scalars.push(disclosed_messages.get(&i).unwrap().0);
            } else {
                C_points_temp.push(generator);
                C_scalars_temp.push(self.m_hat_list[j].0);
                j += 1;
            }
        }

        // Calculate T = H_i1 * msg_i1 + ... H_iR * msg_iR
        let T = G1Projective::multi_exp(&T_points, &T_scalars);

        // C = T * (-c) + Bbar * r2^ + Abar * z^ +
        //            + H_j1 * m^_j1 + ... + H_jU * m^_jU
        let C_len = 1 + 1 + 1 + self.m_hat_list.len();
        let mut C_points = Vec::with_capacity(C_len);
        let mut C_scalars = Vec::with_capacity(C_len);
        // T * (-c)
        C_points.push(T);
        C_scalars.push(self.c.0);
        // Bbar * r2^
        C_points.push(self.B_bar);
        C_scalars.push(self.r2_hat.0);
        // Abar * z^
        C_points.push(self.A_bar);
        C_scalars.push(self.z_hat.0);
        // H_j1 * m^_j1 + ... + H_jU * m^_jU
        C_points.append(&mut C_points_temp);
        C_scalars.append(&mut C_scalars_temp);

        let C = G1Projective::multi_exp(&C_points, &C_scalars);

        // cv_array = (A', Abar, D, C1, C2, R, i1, ..., iR,  msg_i1, ...,
        //                msg_iR, domain, ph)
        // cv_for_hash = encode_for_hash(cv_array)
        //  if cv_for_hash is INVALID, return INVALID
        //  cv = hash_to_scalar(cv_for_hash, 1)
        let cv = compute_challenge::<_, C>(
            &self.A_bar,
            &self.B_bar,
            &C,
            disclosed_messages,
            &domain,
            ph,
        )?;

        // Check the selective disclosure proof
        // if c != cv, return INVALID
        if self.c != cv {
            return Ok(false);
        }

        // This check is already done during `Proof` deserialization
        // if Abar == 1, return INVALID
        if self.A_bar.is_identity().unwrap_u8() == 1 {
            return Err(Error::PointIsIdentity);
        }

        // Check the signature proof
        // if e(Abar, W) * e(Abar, -P2) != 1, return INVALID
        // else return VALID
        let P2 = C::p2().to_affine();
        Ok(Bls12::multi_miller_loop(&[
            (&self.A_bar.to_affine(), &G2Prepared::from(PK.0.to_affine())),
            (&self.B_bar.to_affine(), &G2Prepared::from(-P2)),
        ])
        .final_exponentiation()
        .is_identity()
        .unwrap_u8()
            == 1)
    }

    /// Return the size of proof in bytes for `num_undisclosed_messages`.
    pub fn get_size(num_undisclosed_messages: usize) -> usize {
        OCTET_POINT_G1_LENGTH * 2
            + OCTET_SCALAR_LENGTH * (3 + num_undisclosed_messages)
    }

    /// Store the proof as a sequence of bytes in big endian format.
    /// This method implements `ProofToOctets` API as defined in BBS specification <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-prooftooctets>.
    /// Each member of the struct is serialized to big-endian format.
    /// Needs `OCTET_POINT_G1_LENGTH * 2 + OCTET_SCALAR_LENGTH * (3 + U)` space
    /// where     
    ///    `OCTET_POINT_G1_LENGTH`, size of a point in `G1` in compressed form,
    ///    `OCTET_SCALAR_LENGTH`, size of a `Scalar`, and
    ///    `U` number of unrevealed messages.
    /// For BLS12-381 based implementation, OCTET_POINT_G1_LENGTH is 48 bytes,
    /// and OCTET_SCALAR_LENGTH is 32 bytes, then for
    /// proof = (Abar, Bbar, c, r2^, z^, (m^_1, ..., m^_U)), and
    /// bytes sequence will be [48, 48, 32, 32, 32, 32*U ].
    pub fn to_octets(&self) -> Vec<u8> {
        let size = OCTET_POINT_G1_LENGTH * 2
            + OCTET_SCALAR_LENGTH * (3 + self.m_hat_list.len());

        let mut buffer = Vec::with_capacity(size);

        // proof = (Abar, Bbar, c, r2^, z^, (m^_1, ..., m^_U))
        buffer.extend_from_slice(&point_to_octets_g1(&self.A_bar));
        buffer.extend_from_slice(&point_to_octets_g1(&self.B_bar));
        buffer.extend_from_slice(&self.c.to_bytes());
        buffer.extend_from_slice(&self.r2_hat.to_bytes());
        buffer.extend_from_slice(&self.z_hat.to_bytes());
        for i in 0..self.m_hat_list.len() {
            buffer.extend_from_slice(&self.m_hat_list[i].to_bytes());
        }
        buffer
    }

    /// Get the proof `Proof` from a sequence of bytes in big endian format.
    /// This method implements `OctetsToProof` API as defined in BBS specification <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-octetstoproof>.
    /// Each member of `Proof` is deserialized from big-endian bytes.
    /// Expected input size is `OCTET_POINT_G1_LENGTH * 3 + OCTET_SCALAR_LENGTH
    /// * (5 + U)` where `OCTET_POINT_G1_LENGTH`, size of a point in `G1` in
    ///   ompressed form, `OCTET_SCALAR_LENGTH`, size of a `Scalar`, and `U` is
    ///   the number of hidden messages.
    /// For BLS12-381 based implementation, OCTET_POINT_G1_LENGTH is 48 byes,
    /// and OCTET_SCALAR_LENGTH is 32 bytes, then bytes sequence will be
    /// treated as [48, 48, 32, 32, 32, 32*U ] to represent   
    /// proof = (Abar, Bbar, c, r2^, z^, (m^_1, ..., m^_U)).
    pub fn from_octets<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        const PROOF_LEN_FLOOR: usize =
            OCTET_POINT_G1_LENGTH * 2 + OCTET_SCALAR_LENGTH * 3;
        let buffer = bytes.as_ref();
        if buffer.len() < PROOF_LEN_FLOOR {
            return Err(Error::MalformedProof {
                cause: format!(
                    "not enough data, input buffer size: {} bytes",
                    buffer.len()
                ),
            });
        }
        if (buffer.len() - PROOF_LEN_FLOOR) % OCTET_SCALAR_LENGTH != 0 {
            return Err(Error::MalformedProof {
                cause: format!(
                    "variable length proof data size {} is not multiple of \
                     `Scalar` size {} bytes",
                    buffer.len() - PROOF_LEN_FLOOR,
                    OCTET_SCALAR_LENGTH
                ),
            });
        }

        let unrevealed_message_count =
            (buffer.len() - PROOF_LEN_FLOOR) / OCTET_SCALAR_LENGTH;

        let mut offset = 0usize;
        let mut end = OCTET_POINT_G1_LENGTH;

        // Get Abar
        let A_bar = extract_point_value(&mut offset, &mut end, buffer)?;

        // Get B_bar
        let B_bar = extract_point_value(&mut offset, &mut end, buffer)?;

        // Get c
        end = offset + OCTET_SCALAR_LENGTH;
        let c = Challenge::from_bytes(slicer!(
            buffer,
            offset,
            end,
            OCTET_SCALAR_LENGTH
        ));
        if c.is_none().unwrap_u8() == 1u8 {
            return Err(Error::MalformedProof {
                cause: "failure while deserializing `c`".to_owned(),
            });
        }
        let c = c.unwrap();
        if c.0.is_zero().unwrap_u8() == 1u8 {
            return Err(Error::UnexpectedZeroValue);
        }

        offset = end;
        end = offset + OCTET_SCALAR_LENGTH;

        // Get r2^, z^
        let r2_hat = extract_scalar_value(&mut offset, &mut end, buffer)?;
        let z_hat = extract_scalar_value(&mut offset, &mut end, buffer)?;
        // Get  (m^_j1, ..., m^_jU)
        let mut m_hat_list =
            Vec::<FiatShamirProof>::with_capacity(unrevealed_message_count);
        for _ in 0..unrevealed_message_count {
            let m_hat = extract_scalar_value(&mut offset, &mut end, buffer)?;
            m_hat_list.push(m_hat);
        }

        Ok(Self {
            A_bar,
            B_bar,
            c,
            r2_hat,
            z_hat,
            m_hat_list,
        })
    }
}

// Extract a `G1Projective` value from the buffer
fn extract_point_value(
    offset: &mut usize,
    end: &mut usize,
    buffer: &[u8],
) -> Result<G1Projective, Error> {
    let value = octets_to_point_g1(slicer!(
        buffer,
        *offset,
        *end,
        OCTET_POINT_G1_LENGTH
    ))?;
    if value.is_identity().unwrap_u8() == 1 {
        return Err(Error::PointIsIdentity);
    }
    *offset = *end;
    *end += OCTET_POINT_G1_LENGTH;
    Ok(value)
}

// Extract a `FiatShamirProof` value from the buffer
fn extract_scalar_value(
    offset: &mut usize,
    end: &mut usize,
    buffer: &[u8],
) -> Result<FiatShamirProof, Error> {
    let value = FiatShamirProof::from_bytes(slicer!(
        buffer,
        *offset,
        *end,
        OCTET_SCALAR_LENGTH
    ));
    if value.is_none().unwrap_u8() == 1u8 {
        return Err(Error::MalformedProof {
            cause: "failure while deserializing a `Scalar` value".to_owned(),
        });
    }
    let value = value.unwrap();
    if value.0.is_zero().unwrap_u8() == 1u8 {
        return Err(Error::UnexpectedZeroValue);
    }
    *offset = *end;
    *end = *offset + OCTET_SCALAR_LENGTH;
    Ok(value)
}
