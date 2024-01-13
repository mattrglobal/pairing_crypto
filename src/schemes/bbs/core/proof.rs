#![allow(non_snake_case)]

use super::{
    generator::Generators,
    key_pair::PublicKey,
    signature::Signature,
    types::{
        Challenge,
        FiatShamirProof,
        Message,
        ProofInitResult,
        ProofMessage,
        RandomScalars,
    },
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

use super::types::ProofTrace;

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
    /// r2^
    pub(crate) r2_hat: FiatShamirProof,
    /// z^
    pub(crate) z_hat: FiatShamirProof,
    /// (m^_1, ..., m^_U)
    pub(crate) m_hat_list: Vec<FiatShamirProof>,
    /// c
    pub(crate) c: Challenge,
}

impl core::fmt::Display for Proof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Proof(A_bar: ")?;
        print_byte_array!(f, point_to_octets_g1(&self.A_bar));
        write!(f, ", B_bar: ")?;
        print_byte_array!(f, point_to_octets_g1(&self.B_bar));
        write!(f, ", r2^: {}, z^: {}, m^_i: [", self.r2_hat.0, self.z_hat.0,)?;
        for (i, m_hat) in self.m_hat_list.iter().enumerate() {
            write!(f, "m^_{}: {}, ", i + 1, m_hat.0)?;
        }
        write!(f, "], c: {})", self.c.0)
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

    pub fn new_with_rng<T, R, G, C>(
        PK: &PublicKey,
        signature: &Signature,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        messages: &[ProofMessage],
        rng: R,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        R: RngCore + CryptoRng,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        Self::new_with_rng_and_trace::<_, _, _, C>(
            PK, signature, header, ph, generators, messages, rng, None,
        )
    }

    #[cfg(feature = "__private_bbs_fixtures_generator_api")]
    pub fn new_with_trace<T, R, G, C>(
        PK: &PublicKey,
        signature: &Signature,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        messages: &[ProofMessage],
        rng: R,
        trace: Option<&mut ProofTrace>,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        R: RngCore + CryptoRng,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        Self::new_with_rng_and_trace::<_, _, _, C>(
            PK, signature, header, ph, generators, messages, rng, trace,
        )
    }

    /// Generates the zero-knowledge proof-of-knowledge of a signature, while
    /// optionally selectively disclosing from the original set of signed messages as defined in `ProofGen` API in BBS Signature specification <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofgen> using an externally supplied random number generator.
    #[allow(clippy::too_many_arguments)]
    fn new_with_rng_and_trace<T, R, G, C>(
        PK: &PublicKey,
        signature: &Signature,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        messages: &[ProofMessage],
        mut rng: R,
        mut trace: Option<&mut ProofTrace>,
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

        // (r1, r2, r3, m~_j1, ..., m~_jU) = calculate_random_scalars(3+U)
        let mut random_scalars = RandomScalars {
            r1: create_random_scalar(&mut rng)?,
            r2_tilde: create_random_scalar(&mut rng)?,
            z_tilde: create_random_scalar(&mut rng)?,
            ..Default::default()
        };

        // Deserialization steps of the `CoreProofGen` operation defined in https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreproofgen
        //
        // Deserialization:
        // ...(implicit steps)...
        // 9. undisclosed_indexes = range(1, L) \ disclosed_indexes
        // 10. disclosed_messages = (messages[i1], ..., messages[iR])
        let message_scalars: Vec<Scalar> =
            messages.iter().map(|m| m.get_message().0).collect();
        let mut undisclosed_indexes = Vec::new();
        let mut disclosed_messages = BTreeMap::new();
        let mut undisclosed_message_scalars = Vec::new();
        for (i, message) in messages.iter().enumerate() {
            match message {
                ProofMessage::Revealed(m) => {
                    disclosed_messages.insert(i, *m);
                }
                ProofMessage::Hidden(m) => {
                    undisclosed_indexes.push(i);
                    undisclosed_message_scalars.push(m.0);

                    // Get the random scalars m~_j1, ..., m~_jU
                    random_scalars
                        .insert_m_tilde(create_random_scalar(&mut rng)?);
                }
            }
        }

        // initialize proof generation
        let init_result: ProofInitResult = Self::proof_init::<T, G, C>(
            PK,
            signature,
            generators,
            &random_scalars,
            header,
            message_scalars,
            undisclosed_indexes,
        )?;

        // calculate the challenge
        let c =
            compute_challenge::<_, C>(&init_result, &disclosed_messages, ph)?;

        // Add to the trace when creating the fixtures
        if cfg!(feature = "__private_bbs_fixtures_generator_api") {
            if let Some(t) = trace.as_mut() {
                (*t).new_from_init_res(&init_result);
                t.challenge = c.0.to_bytes_be();
                t.random_scalars = random_scalars.clone();
            }
        }

        // finalize the proof
        Self::proof_finalize(
            c,
            signature.e,
            random_scalars,
            init_result,
            undisclosed_message_scalars,
        )
    }

    /// Verify the zero-knowledge proof-of-knowledge of a signature with
    /// optionally selectively disclosed messages from the original set of signed messages as defined in `ProofGen` API in BBS Signature specification <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofverify>.
    pub fn verify<T, G, C>(
        &self,
        PK: &PublicKey,
        header: Option<T>,
        ph: Option<T>,
        generators: &G,
        disclosed_messages: &BTreeMap<usize, Message>,
    ) -> Result<bool, Error>
    where
        T: AsRef<[u8]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        // if KeyValidate(PK) is INVALID, return INVALID
        // `PK` should not be an identity and should belong to subgroup G2
        if PK.is_valid().unwrap_u8() == 0u8 {
            return Err(Error::InvalidPublicKey);
        }

        // initialize the proof verification procedure
        let init_res = self.proof_verify_init::<T, G, C>(
            PK,
            header,
            generators,
            disclosed_messages,
        )?;

        // cv_array = (A', Abar, D, C1, C2, R, i1, ..., iR,  msg_i1, ...,
        //                msg_iR, domain, ph)
        // cv_for_hash = encode_for_hash(cv_array)
        //  if cv_for_hash is INVALID, return INVALID
        //  cv = hash_to_scalar(cv_for_hash, 1)
        let cv = compute_challenge::<_, C>(&init_res, disclosed_messages, ph)?;

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

    /// Initialize the Proof Generation operation.
    pub fn proof_init<T, G, C>(
        PK: &PublicKey,
        signature: &Signature,
        generators: &G,
        random_scalars: &RandomScalars,
        header: Option<T>,
        message_scalars: Vec<Scalar>,
        undisclosed_indexes: Vec<usize>,
    ) -> Result<ProofInitResult, Error>
    where
        T: AsRef<[u8]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        let total_no_of_messages = message_scalars.len();

        // Check input sizes.
        // Number of message generators == number of messages is checked in
        // compute_domain. Checking that all the indexes are in the [0,
        // length(messages)) range is done before get_message_generator
        // bellow. Checking here that number of random scalars == number
        // of messages + 3.
        if undisclosed_indexes.len() != random_scalars.m_tilde_scalars_len() {
            return Err(Error::UndisclosedIndexesRandomScalarsLengthMismatch {
                random_scalars: random_scalars.m_tilde_scalars_len(),
                undisclosed_indexes: undisclosed_indexes.len(),
            });
        }

        // Checking that number of undisclosed messages (/indexes) <= number of
        // messages
        if undisclosed_indexes.len() > message_scalars.len() {
            return Err(Error::BadParams {
                cause: format!(
                    "Not disclosed messages number is invalid. Maximum \
                     allowed value is {}",
                    total_no_of_messages
                ),
            });
        }

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        let domain = compute_domain::<_, _, C>(
            PK,
            header,
            message_scalars.len(),
            generators,
        )?;

        // Abar = A * r1
        let A_bar = signature.A * random_scalars.r1;

        // B = P1 + Q * domain + H_1 * msg_1 + ... + H_L * msg_L
        let B = compute_B::<_, C>(&domain, &message_scalars, generators)?;

        // Bbar = B * r1 - Abar * e
        let B_bar = G1Projective::multi_exp(
            &[B, A_bar],
            &[random_scalars.r1, -signature.e],
        );

        // T = Abar * r2~ + Bbar * z~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
        let mut H_Points = Vec::new();
        for idx in undisclosed_indexes {
            if idx >= total_no_of_messages {
                return Err(Error::BadParams {
                    cause: format!(
                        "Undisclosed message index is invalid. Maximum \
                         allowed value is {}",
                        total_no_of_messages - 1
                    ),
                });
            }
            // unwrap is safe here since we check the idx value above.
            let generator = generators.get_message_generator(idx).unwrap();
            H_Points.push(generator);
        }

        let T = G1Projective::multi_exp(
            &[[A_bar, B_bar].to_vec(), H_Points].concat(),
            &[
                [random_scalars.r2_tilde, random_scalars.z_tilde].to_vec(),
                random_scalars.m_tilde_scalars.to_vec(),
            ]
            .concat(),
        );

        Ok(ProofInitResult {
            A_bar,
            B_bar,
            T,
            domain,
        })
    }

    /// Finalize the Proof Generation operation.
    pub fn proof_finalize(
        challenge: Challenge,
        e_value: Scalar,
        random_scalars: RandomScalars,
        init_res: ProofInitResult,
        undisclosed_message_scalars: Vec<Scalar>,
    ) -> Result<Proof, Error> {
        // Check that number of random scalars == number of messages + 3
        if undisclosed_message_scalars.len()
            != random_scalars.m_tilde_scalars_len()
        {
            return Err(Error::UndisclosedIndexesRandomScalarsLengthMismatch {
                random_scalars: random_scalars.m_tilde_scalars_len(),
                undisclosed_indexes: undisclosed_message_scalars.len(),
            });
        }

        // r2 = -r1 ^ -1 mod r
        let r2 = random_scalars.r1.invert();

        if r2.is_none().unwrap_u8() == 1u8 {
            return Err(Error::CryptoOps {
                cause: "Failed to invert `r1`".to_owned(),
            });
        };
        let r2 = -r2.unwrap();

        // r2^ = r2~ + c * r2
        let r2_hat = FiatShamirProof(
            random_scalars.r2_tilde + challenge.0 * e_value * r2,
        );

        // z^ = z~ + c * e * r2
        let z_hat = FiatShamirProof(random_scalars.z_tilde + challenge.0 * r2);

        // for j in (j1, j2,..., jU): m^_j = m~_j + c * msg_j
        let m_hat_list = random_scalars
            .m_tilde_scalars
            .iter()
            .zip(undisclosed_message_scalars.iter())
            .map(|(m_tilde, msg)| {
                let m_hat = *m_tilde + challenge.0 * (*msg);
                FiatShamirProof(m_hat)
            })
            .collect::<Vec<FiatShamirProof>>();

        Ok(Proof {
            A_bar: init_res.A_bar,
            B_bar: init_res.B_bar,
            r2_hat,
            z_hat,
            m_hat_list,
            c: challenge,
        })
    }

    /// Initialize the Proof Verification operation.
    pub fn proof_verify_init<T, G, C>(
        &self,
        PK: &PublicKey,
        header: Option<T>,
        generators: &G,
        disclosed_messages: &BTreeMap<usize, Message>,
    ) -> Result<ProofInitResult, Error>
    where
        T: AsRef<[u8]>,
        G: Generators,
        C: BbsCiphersuiteParameters,
    {
        // The total number of messages equals disclosed_messages number + m_hat
        // number Note that this operation is necessarily repeated at
        // the proof verify api.
        let total_no_of_messages =
            self.m_hat_list.len() + disclosed_messages.len();

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

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        let domain = compute_domain::<_, _, C>(
            PK,
            header,
            generators.message_generators_length(),
            generators,
        )?;

        // D = P1 + Q * domain + H_i1 * msg_i1 + ... H_iR * msg_iR
        let D_len = 1 + 1 + disclosed_messages.len();
        let mut D_points = Vec::with_capacity(D_len);
        let mut D_scalars = Vec::with_capacity(D_len);
        let P1 = C::p1()?;
        // P1
        D_points.push(P1);
        D_scalars.push(Scalar::one());
        // Q * domain
        D_points.push(generators.Q());
        D_scalars.push(domain);

        let mut C_points_temp = Vec::with_capacity(self.m_hat_list.len());
        let mut C_scalars_temp = Vec::with_capacity(self.m_hat_list.len());
        let mut j = 0;
        for (i, generator) in generators.message_generators_iter().enumerate() {
            if disclosed_messages.contains_key(&i) {
                D_points.push(generator);
                // unwrap() is safe here since we already have checked for
                // existence of key
                D_scalars.push(disclosed_messages.get(&i).unwrap().0);
            } else {
                C_points_temp.push(generator);
                C_scalars_temp.push(self.m_hat_list[j].0);
                j += 1;
            }
        }

        // Calculate D = H_i1 * msg_i1 + ... H_iR * msg_iR
        let D = G1Projective::multi_exp(&D_points, &D_scalars);

        // T = D * c + Abar * r2^ + Bbar * z^ +
        //            + H_j1 * m^_j1 + ... + H_jU * m^_jU
        let T_len = 1 + 1 + 1 + self.m_hat_list.len();
        let mut T_points = Vec::with_capacity(T_len);
        let mut T_scalars = Vec::with_capacity(T_len);
        // T * (-c)
        T_points.push(D);
        T_scalars.push(self.c.0);
        // Abar * r2^
        T_points.push(self.A_bar);
        T_scalars.push(self.r2_hat.0);
        // Bbar * z^
        T_points.push(self.B_bar);
        T_scalars.push(self.z_hat.0);
        // H_j1 * m^_j1 + ... + H_jU * m^_jU
        T_points.append(&mut C_points_temp);
        T_scalars.append(&mut C_scalars_temp);

        let T = G1Projective::multi_exp(&T_points, &T_scalars);

        Ok(ProofInitResult {
            A_bar: self.A_bar,
            B_bar: self.B_bar,
            T,
            domain,
        })
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
        buffer.extend_from_slice(&self.r2_hat.to_bytes());
        buffer.extend_from_slice(&self.z_hat.to_bytes());
        for i in 0..self.m_hat_list.len() {
            buffer.extend_from_slice(&self.m_hat_list[i].to_bytes());
        }
        buffer.extend_from_slice(&self.c.to_bytes());
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

        // Get c
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

        Ok(Self {
            A_bar,
            B_bar,
            r2_hat,
            z_hat,
            m_hat_list,
            c,
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
