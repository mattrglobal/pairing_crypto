#![allow(non_snake_case)]

use super::{
    constants::{OCTET_POINT_G1_LENGTH, OCTET_SCALAR_LENGTH},
    generator::Generators,
    key_pair::PublicKey,
    signature::Signature,
    types::{Challenge, FiatShamirProof, Message, ProofMessage},
    utils::{
        compute_B,
        compute_challenge,
        compute_domain,
        octets_to_point_g1,
        point_to_octets_g1,
    },
};
use crate::{
    curves::bls12_381::{Bls12, G1Projective, G2Affine, G2Prepared, Scalar},
    error::Error,
    print_byte_array,
};
use core::{convert::TryFrom, fmt::Debug};
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve, Group};
use hashbrown::HashSet;
use log::trace;
use pairing::{MillerLoopResult as _, MultiMillerLoop};
use rand::{CryptoRng, RngCore};
use rand_core::OsRng;

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
#[derive(Debug, Clone, Default)]
pub(crate) struct Proof {
    /// A'
    pub(crate) A_prime: G1Projective,
    /// \overline{A}
    pub(crate) A_bar: G1Projective,
    /// D
    pub(crate) D: G1Projective,
    /// c
    pub(crate) c: Challenge,
    /// e^
    pub(crate) e_hat: FiatShamirProof,
    /// r2^
    pub(crate) r2_hat: FiatShamirProof,
    /// r3^
    pub(crate) r3_hat: FiatShamirProof,
    /// s^
    pub(crate) s_hat: FiatShamirProof,
    /// (m^_1, ..., m^_U)
    pub(crate) m_hat_list: Vec<FiatShamirProof>,
}

impl core::fmt::Display for Proof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Proof(A': ")?;
        print_byte_array!(f, point_to_octets_g1(&self.A_prime));
        write!(f, ", A_bar: ")?;
        print_byte_array!(f, point_to_octets_g1(&self.A_bar));
        write!(f, ", D: ")?;
        print_byte_array!(f, point_to_octets_g1(&self.D));
        write!(
            f,
            ", c: {}, e^: {}, r2^: {}, r3^: {}, s^: {}, [",
            self.c.0, self.e_hat.0, self.r2_hat.0, self.r3_hat.0, self.s_hat.0,
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
    pub fn new<T>(
        PK: &PublicKey,
        signature: &Signature,
        header: Option<T>,
        ph: Option<T>,
        generators: &Generators,
        messages: &[ProofMessage],
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]> + Debug,
    {
        Self::new_with_rng(
            PK,
            signature,
            header,
            ph,
            generators,
            messages,
            OsRng::default(),
        )
    }
    /// Generates the zero-knowledge proof-of-knowledge of a signature, while
    /// optionally selectively disclosing from the original set of signed messages as defined in `ProofGen` API in BBS Signature specification <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofgen> using an externally supplied random number generator.
    pub fn new_with_rng<T>(
        PK: &PublicKey,
        signature: &Signature,
        header: Option<T>,
        ph: Option<T>,
        generators: &Generators,
        messages: &[ProofMessage],
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<Self, Error>
    where
        T: AsRef<[u8]> + Debug,
    {
        trace!("proof_gen enter +++");
        trace!("input parameter: {PK:?}");
        trace!("input parameter: {signature:?}");
        match header {
            Some(ref header) => {
                trace!("input parameter header hex:{:?}", hex::encode(header))
            }
            None => trace!("input parameter header None"),
        }
        match ph {
            Some(ref ph) => {
                trace!(
                    "input parameter: presentation-header hex:{:?}",
                    hex::encode(ph)
                )
            }
            None => trace!("input parameter presentation-header: None"),
        }
        trace!("input parameter: {generators:?}",);
        trace!("input parameter: messages {messages:?}");

        // Error out if length of messages and generators are not equal
        if messages.len() != generators.message_blinding_points_length() {
            return Err(Error::MessageGeneratorsLengthMismatch {
                generators: generators.message_blinding_points_length(),
                messages: messages.len(),
            });
        }

        // The following steps from the `ProofGen` operation defined in https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofgen are implicit in this
        // implementation
        // signature_result = octets_to_signature(signature)
        // (i1, i2,..., iR) = RevealedIndexes
        // (j1, j2,..., jU) = [L] \ RevealedIndexes
        // if signature_result is INVALID, return INVALID
        // (A, e, s) = signature_result
        // generators =  (H_s || H_d || H_1 || ... || H_L)

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        let domain = compute_domain(PK, header, messages.len(), generators)?;
        trace!("domain: {domain:?}");

        // (r1, r2, e~, r2~, r3~, s~) = hash_to_scalar(PRF(8*ceil(log2(r))), 6)
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let e_tilde = Scalar::random(&mut rng);
        let r2_tilde = Scalar::random(&mut rng);
        let r3_tilde = Scalar::random(&mut rng);
        let s_tilde = Scalar::random(&mut rng);
        trace!(
            "randoms r1: {r1:?}, r2: {r2:?}, e~: {e_tilde:?}, r2~: \
             {r2_tilde:?}, r3~: {r3_tilde:?}, s~: {s_tilde:?}"
        );

        // (m~_j1, ..., m~_jU) =  hash_to_scalar(PRF(8*ceil(log2(r))), U)
        // these random scalars will be generated further below using
        // ProofCommittedBuilder::commit_random(...) in `proof2` variable

        let msg: Vec<_> = messages.iter().map(|m| m.get_message()).collect();
        // B = P1 + H_s * s + H_d * domain + H_1 * msg_1 + ... + H_L * msg_L
        let B = compute_B(&signature.s, &domain, msg.as_ref(), generators)?;
        trace!("B: {B:?}");

        // r3 = r1 ^ -1 mod r
        let r3 = r1.invert();
        if r3.is_none().unwrap_u8() == 1u8 {
            return Err(Error::CryptoOps {
                cause: "Failed to invert `r3`".to_owned(),
            });
        };
        let r3 = r3.unwrap();
        trace!("r3: {r3:?}");

        // A' = A * r1
        let A_prime = signature.A * r1;
        trace!("A': {A_prime:?}");

        // Abar = A' * (-e) + B * r1
        let A_bar = G1Projective::multi_exp(&[A_prime, B], &[-signature.e, r1]);
        trace!("A_bar': {A_bar:?}");

        // D = B * r1 + H_s * r2
        let D = G1Projective::multi_exp(&[B, generators.H_s()], &[r1, r2]);
        trace!("D: {D:?}");

        // s' = s + r2 * r3
        let s_prime = signature.s + r2 * r3;
        trace!("s': {s_prime:?}");

        // C1 = A' * e~ + H_s * r2~
        let C1 = G1Projective::multi_exp(
            &[A_prime, generators.H_s()],
            &[e_tilde, r2_tilde],
        );
        trace!("C1: {:?}", C1.to_affine());

        //  C2 = D * (-r3~) + H_s * s~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
        let mut H_points = Vec::new();
        let mut m_tilde_scalars = Vec::new();
        let mut hidden_messages = Vec::new();
        for (i, generator) in
            generators.message_blinding_points_iter().enumerate()
        {
            if let ProofMessage::Hidden(m) = messages[i] {
                H_points.push(*generator);
                m_tilde_scalars.push(Scalar::random(&mut rng));
                hidden_messages.push(m.0);
            }
        }
        let C2 = G1Projective::multi_exp(
            &[[D, generators.H_s()].to_vec(), H_points.clone()].concat(),
            &[[-r3_tilde, s_tilde].to_vec(), m_tilde_scalars.clone()].concat(),
        );
        trace!("H_j1...H_jU: {H_points:?}");
        trace!("m~_j1...m~_jU: {m_tilde_scalars:?}");
        trace!("C2: {:?}", C2.to_affine());

        // c = hash_to_scalar((PK || A' || Abar || D || C1 || C2 || ph), 1)
        let c = compute_challenge(PK, &A_prime, &A_bar, &D, &C1, &C2, ph)?;

        // e^ = e~ + c * e
        let e_hat = FiatShamirProof(e_tilde + c.0 * signature.e);

        // r2^ = r2~ + c * r2
        let r2_hat = FiatShamirProof(r2_tilde + c.0 * r2);

        // r3^ = r3~ + c * r3
        let r3_hat = FiatShamirProof(r3_tilde + c.0 * r3);

        // s^ = s~ + c * s'
        let s_hat = FiatShamirProof(s_tilde + c.0 * s_prime);

        // for j in (j1, j2,..., jU): m^_j = m~_j + c * msg_j
        let m_hat_list = m_tilde_scalars
            .iter()
            .zip(hidden_messages.iter())
            .map(|(m_tilde, msg)| {
                let m_hat = *m_tilde + c.0 * (*msg);
                FiatShamirProof(m_hat)
            })
            .collect::<Vec<FiatShamirProof>>();
        let proof = Proof {
            A_prime,
            A_bar,
            D,
            c,
            e_hat,
            r2_hat,
            r3_hat,
            s_hat,
            m_hat_list,
        };

        trace!("generated proof: {proof:?}");
        trace!("proof_gen exit ---");
        Ok(proof)
    }

    /// Verify the zero-knowledge proof-of-knowledge of a signature with
    /// optionally selectively disclosed messages from the original set of signed messages as defined in `ProofGen` API in BBS Signature specification <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofverify>.
    pub fn verify<T>(
        &self,
        PK: &PublicKey,
        header: Option<T>,
        ph: Option<T>,
        generators: &Generators,
        revealed_msgs: &[(usize, Message)],
    ) -> Result<bool, Error>
    where
        T: AsRef<[u8]> + Debug,
    {
        trace!("proof_verify enter +++");
        trace!("input parameter: Self(proof) {self:?}");
        trace!("input parameter: {PK:?}");
        match header {
            Some(ref header) => {
                trace!("input parameter header hex:{:?}", hex::encode(header))
            }
            None => trace!("input parameter header: None"),
        }
        match ph {
            Some(ref ph) => {
                trace!(
                    "input parameter presentation-header hex:{:?}",
                    hex::encode(ph)
                )
            }
            None => trace!("input parameter presentation-header: None"),
        }
        trace!("input parameter: {generators:?}",);
        trace!("input parameters: revealed-messages {revealed_msgs:?}");

        // Input parameter checks
        if self.m_hat_list.len() + revealed_msgs.len()
            != generators.message_blinding_points_length()
        {
            return Err(Error::BadParams {
                cause: format!(
                    "Incorrect number of messages and generators: \
                     [#generators: {}, #hidden_messages: {}, \
                     #revealed_messages: {}]",
                    generators.message_blinding_points_length(),
                    self.m_hat_list.len(),
                    revealed_msgs.len()
                ),
            });
        }

        // if KeyValidate(PK) is INVALID, return INVALID
        // `PK` should not be an identity and should belong to subgroup G2
        if PK.is_valid().unwrap_u8() == 0 {
            return Err(Error::InvalidPublicKey);
        }

        // The following steps from the `ProofVerify` operation defined in https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofverify are implicit in this
        // implementation
        // (i1, i2, ..., iR) = RevealedIndexes
        // (j1, j2, ..., jU) = [L]\RevealedIndexes
        // proof_value = octets_to_proof(proof)
        // if proof_value is INVALID, return INVALID
        // (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1,...,m^_jU)) = proof_value
        // generators =  (H_s || H_d || H_1 || ... || H_L)

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        let domain = compute_domain(
            PK,
            header,
            generators.message_blinding_points_length(),
            generators,
        )?;
        trace!("domain: {domain:?}");

        // C1 = (Abar - D) * c + A' * e^ + H_s * r2^
        let C1_points = [self.A_bar - self.D, self.A_prime, generators.H_s()];
        let C1_scalars = [self.c.0, self.e_hat.0, self.r2_hat.0];
        let C1 = G1Projective::multi_exp(&C1_points, &C1_scalars);
        trace!("C1: {:?}", C1.to_affine());

        // T = P1 + H_d * domain + H_i1 * msg_i1 + ... H_iR * msg_iR
        let T_len = 1 + 1 + revealed_msgs.len();
        let mut T_points = Vec::with_capacity(T_len);
        let mut T_scalars = Vec::with_capacity(T_len);
        let P1 = G1Projective::generator();
        // P1
        T_points.push(P1);
        T_scalars.push(Scalar::one());
        // H_d * domain
        T_points.push(generators.H_d());
        T_scalars.push(domain);
        // H_i1 * msg_i1 + ... H_iR * msg_iR
        let mut revealed = HashSet::new();
        for (idx, msg) in revealed_msgs {
            revealed.insert(*idx);
            if let Some(g) = generators.get_message_blinding_point(*idx) {
                T_points.push(g);
                T_scalars.push(msg.0);
            } else {
                // as we have already check about length, this should not happen
                return Err(Error::BadParams {
                    cause: "Generators out of range".to_owned(),
                });
            }
        }
        // Calculate T
        let T = G1Projective::multi_exp(&T_points, &T_scalars);
        trace!("T: {T:?}");

        // Compute C2 = T * c + D * (-r3^) + H_s * s^ +
        //           H_j1 * m^_j1 + ... + H_jU * m^_jU
        let C2_len = 1 + 1 + 1 + self.m_hat_list.len();
        let mut C2_points = Vec::with_capacity(C2_len);
        let mut C2_scalars = Vec::with_capacity(C2_len);
        // T*c
        C2_points.push(T);
        C2_scalars.push(self.c.0);
        // D * (-r3^)
        C2_points.push(self.D);
        C2_scalars.push(-self.r3_hat.0);
        // H_s * s^
        C2_points.push(generators.H_s());
        C2_scalars.push(self.s_hat.0);
        // H_j1 * m^_j1 + ... + H_jU * m^_jU
        let mut j = 0;
        for (i, generator) in
            generators.message_blinding_points_iter().enumerate()
        {
            if revealed.contains(&i) {
                continue;
            }
            C2_points.push(*generator);
            C2_scalars.push(self.m_hat_list[j].0);
            j += 1;
        }
        let C2 = G1Projective::multi_exp(&C2_points, &C2_scalars);
        trace!("C2: {:?}", C2.to_affine());

        // cv = hash_to_scalar((PK || A' || Abar || D || C1 || C2 || ph), 1)
        let cv = compute_challenge(
            PK,
            &self.A_prime,
            &self.A_bar,
            &self.D,
            &C1,
            &C2,
            ph,
        )?;
        trace!("cv: {cv:?}");

        // Check the selective disclosure proof
        // if c != cv, return INVALID
        if self.c != cv {
            return Ok(false);
        }

        // This check is already done during `Proof` deserialization
        // if A' == 1, return INVALID
        if self.A_prime.is_identity().unwrap_u8() == 1 {
            return Err(Error::PointIsIdentity);
        }

        // Check the signature proof
        // if e(A', W) * e(Abar, -P2) != 1, return INVALID
        // else return VALID
        let P2 = G2Affine::generator();
        let result = Bls12::multi_miller_loop(&[
            (
                &self.A_prime.to_affine(),
                &G2Prepared::from(PK.0.to_affine()),
            ),
            (&self.A_bar.to_affine(), &G2Prepared::from(-P2)),
        ])
        .final_exponentiation()
        .is_identity()
        .unwrap_u8()
            == 1;
        trace!("result: {result}");
        trace!("proof_verify exit ---");
        Ok(result)
    }

    /// Store the proof as a sequence of bytes in big endian format.
    /// This method implements `ProofToOctets` API as defined in BBS specification <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-prooftooctets>.
    /// Each member of the struct is serialized to big-endian format.
    /// Needs `OCTET_POINT_G1_LENGTH * 3 + OCTET_SCALAR_LENGTH * (5 + U)` space
    /// where     
    ///    `OCTET_POINT_G1_LENGTH`, size of a point in `G1` in compressed form,
    ///    `OCTET_SCALAR_LENGTH`, size of a `Scalar`, and
    ///    `U` number of unrevealed messages.
    /// For BLS12-381 based implementation, OCTET_POINT_G1_LENGTH is 48 byes,
    /// and OCTET_SCALAR_LENGTH is 32 bytes, then for
    /// proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_1, ..., m^_U)), and
    /// bytes sequence will be [48, 48, 48, 32, 32, 32, 32, 32, 32*U ].
    pub fn to_octets(&self) -> Vec<u8> {
        let size = OCTET_POINT_G1_LENGTH * 3
            + OCTET_SCALAR_LENGTH * (5 + self.m_hat_list.len());

        let mut buffer = Vec::with_capacity(size);

        // proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1, ..., m^_jU))
        buffer.extend_from_slice(&point_to_octets_g1(&self.A_prime));
        buffer.extend_from_slice(&point_to_octets_g1(&self.A_bar));
        buffer.extend_from_slice(&point_to_octets_g1(&self.D));
        buffer.extend_from_slice(&self.c.to_bytes());
        buffer.extend_from_slice(&self.e_hat.to_bytes());
        buffer.extend_from_slice(&self.r2_hat.to_bytes());
        buffer.extend_from_slice(&self.r3_hat.to_bytes());
        buffer.extend_from_slice(&self.s_hat.to_bytes());
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
    /// treated as [48, 48, 48, 32, 32, 32, 32, 32, 32*U ] to represent   
    /// proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_1, ..., m^_U)).
    pub fn from_octets<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        const PROOF_LEN_FLOOR: usize =
            OCTET_POINT_G1_LENGTH * 3 + OCTET_SCALAR_LENGTH * 5;
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
                    "variable length proof data {} is not multiple of \
                     `Scalar` size {} bytes",
                    buffer.len() - OCTET_POINT_G1_LENGTH,
                    OCTET_SCALAR_LENGTH
                ),
            });
        }

        let unrevealed_message_count =
            (buffer.len() - PROOF_LEN_FLOOR) / OCTET_SCALAR_LENGTH;

        let mut offset = 0usize;
        let mut end = OCTET_POINT_G1_LENGTH;

        // Get A_prime
        let A_prime = extract_point_value(&mut offset, &mut end, buffer)?;

        // Get A_bar
        let A_bar = extract_point_value(&mut offset, &mut end, buffer)?;

        // Get D
        let D = extract_point_value(&mut offset, &mut end, buffer)?;

        // Get c
        end = offset + OCTET_SCALAR_LENGTH;
        let c = Challenge::from_bytes(slicer!(
            buffer,
            offset,
            end,
            OCTET_SCALAR_LENGTH
        ));
        if c.is_none().unwrap_u8() == 1 {
            return Err(Error::MalformedProof {
                cause: "failure while deserializing `c`".to_owned(),
            });
        }
        offset = end;
        end = offset + OCTET_SCALAR_LENGTH;
        let c = c.unwrap();

        // Get e^, r2^, r3^, s^
        let e_hat = extract_scalar_value(&mut offset, &mut end, buffer)?;
        let r2_hat = extract_scalar_value(&mut offset, &mut end, buffer)?;
        let r3_hat = extract_scalar_value(&mut offset, &mut end, buffer)?;
        let s_hat = extract_scalar_value(&mut offset, &mut end, buffer)?;
        // Get  (m^_j1, ..., m^_jU)
        let mut m_hat_list =
            Vec::<FiatShamirProof>::with_capacity(unrevealed_message_count);
        for _ in 0..unrevealed_message_count {
            let m_hat = extract_scalar_value(&mut offset, &mut end, buffer)?;
            m_hat_list.push(m_hat);
        }

        Ok(Self {
            A_prime,
            A_bar,
            D,
            c,
            e_hat,
            r2_hat,
            r3_hat,
            s_hat,
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
    if value.is_none().unwrap_u8() == 1 {
        return Err(Error::MalformedProof {
            cause: "failure while deserializing a value".to_owned(),
        });
    }
    *offset = *end;
    *end = *offset + OCTET_SCALAR_LENGTH;
    Ok(value.unwrap())
}
