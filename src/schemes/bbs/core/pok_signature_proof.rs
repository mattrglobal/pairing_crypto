#![allow(non_snake_case)]

use super::{
    constants::{g1_affine_compressed_size, scalar_size},
    generator::Generators,
    public_key::PublicKey,
    types::{Challenge, Message, PresentationMessage},
    utils::compute_domain,
};
use crate::{
    curves::bls12_381::{
        Bls12,
        G1Affine,
        G1Projective,
        G2Affine,
        G2Prepared,
        Scalar,
    },
    error::Error,
};
use core::convert::TryFrom;
use digest::Update;
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve, Group, GroupEncoding};
use hashbrown::HashSet;
use pairing::{MillerLoopResult as _, MultiMillerLoop};
use serde::{Deserialize, Serialize};
use subtle::{Choice, CtOption};

/// Convert slice to a fixed array
macro_rules! slicer {
    ($d:expr, $b:expr, $e:expr, $s:expr) => {
        &<[u8; $s]>::try_from(&$d[$b..$e]).unwrap()
    };
}

/// The actual proof that is sent from prover to verifier.
///
/// Contains the proof of 2 discrete log relations.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PokSignatureProof {
    /// A'
    pub(crate) A_prime: G1Projective,
    /// \overline{A}
    pub(crate) A_bar: G1Projective,
    /// D
    pub(crate) D: G1Projective,
    pub(crate) proofs1: [Challenge; 2],
    pub(crate) proofs2: Vec<Challenge>,
    pub(crate) challenge: Challenge,
    pub(crate) hidden_message_count: usize,
}

impl PokSignatureProof {
    const FIELD_BYTES: usize = scalar_size();
    const COMMITMENT_G1_BYTES: usize = g1_affine_compressed_size();

    /// Store the proof as a sequence of bytes
    /// Each point is compressed to big-endian format
    /// Needs 32 * (N + 2) + 48 * 3 space otherwise it will panic
    /// where N is the number of hidden messages
    /// [48,    ,48    ,48 ,64(2*32)          , 32*N]
    /// [a_prime, a_bar, d, proof1(2 of these), [0...N]]
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = Self::FIELD_BYTES * (3 + self.proofs2.len())
            + Self::COMMITMENT_G1_BYTES * 3;
        let mut buffer = Vec::with_capacity(size);

        buffer.extend_from_slice(&self.A_prime.to_affine().to_compressed());
        buffer.extend_from_slice(&self.A_bar.to_affine().to_compressed());
        buffer.extend_from_slice(&self.D.to_affine().to_compressed());
        buffer.extend_from_slice(&self.challenge.to_bytes());

        for i in 0..self.proofs1.len() {
            buffer.extend_from_slice(&self.proofs1[i].to_bytes());
        }
        for i in 0..self.proofs2.len() {
            buffer.extend_from_slice(&self.proofs2[i].to_bytes());
        }
        buffer
    }

    // TODO update the expected sizes here
    /// Expected size is (N + 1) * 32 + 48 bytes
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        let size = Self::FIELD_BYTES * 5 + Self::COMMITMENT_G1_BYTES * 3;
        let buffer = bytes.as_ref();
        if buffer.len() < size {
            return None;
        }
        if (buffer.len() - Self::COMMITMENT_G1_BYTES) % Self::FIELD_BYTES != 0 {
            return None;
        }

        let hidden_message_count = (buffer.len() - size) / Self::FIELD_BYTES;
        let mut offset = Self::COMMITMENT_G1_BYTES;
        let mut end = 2 * Self::COMMITMENT_G1_BYTES;
        let A_prime = G1Affine::from_compressed(slicer!(
            buffer,
            0,
            offset,
            Self::COMMITMENT_G1_BYTES
        ))
        .map(G1Projective::from);
        let A_bar = G1Affine::from_compressed(slicer!(
            buffer,
            offset,
            end,
            Self::COMMITMENT_G1_BYTES
        ))
        .map(G1Projective::from);
        offset = end;
        end = offset + Self::COMMITMENT_G1_BYTES;
        let D = G1Affine::from_compressed(slicer!(
            buffer,
            offset,
            end,
            Self::COMMITMENT_G1_BYTES
        ))
        .map(G1Projective::from);

        if A_prime.is_none().unwrap_u8() == 1
            || A_bar.is_none().unwrap_u8() == 1
            || D.is_none().unwrap_u8() == 1
        {
            return None;
        }

        offset = end;
        end = offset + Self::FIELD_BYTES;
        let challenge = Challenge::from_bytes(slicer!(
            buffer,
            offset,
            end,
            Self::FIELD_BYTES
        ));
        offset = end;
        end = offset + Self::FIELD_BYTES;

        let mut proofs1 = [
            CtOption::new(Challenge::default(), Choice::from(0u8)),
            CtOption::new(Challenge::default(), Choice::from(0u8)),
        ];
        for proof in &mut proofs1 {
            *proof = Challenge::from_bytes(slicer!(
                buffer,
                offset,
                end,
                Self::FIELD_BYTES
            ));
            offset = end;
            end = offset + Self::FIELD_BYTES;
        }
        if proofs1[0].is_none().unwrap_u8() == 1
            || proofs1[1].is_none().unwrap_u8() == 1
        {
            return None;
        }

        let mut proofs2 =
            Vec::<Challenge>::with_capacity(hidden_message_count + 2);
        for _ in 0..(hidden_message_count + 2) {
            let c = Challenge::from_bytes(slicer!(
                buffer,
                offset,
                end,
                Self::FIELD_BYTES
            ));
            offset = end;
            end = offset + Self::FIELD_BYTES;
            if c.is_none().unwrap_u8() == 1 {
                return None;
            }

            proofs2.push(c.unwrap());
        }
        Some(Self {
            A_prime: A_prime.unwrap(),
            A_bar: A_bar.unwrap(),
            D: D.unwrap(),
            challenge: challenge.unwrap(),
            proofs1: [proofs1[0].unwrap(), proofs1[1].unwrap()],
            proofs2,
            hidden_message_count,
        })
    }

    /// Convert the committed values to bytes for the fiat-shamir challenge as
    /// defined in `ProofVerify` API in BBS Signature spec <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.7>
    #[allow(clippy::too_many_arguments)]
    pub fn add_challenge_contribution<T>(
        &self,
        PK: &PublicKey,
        header: T,
        generators: &Generators,
        rvl_msgs: &[(usize, Message)],
        ph: &PresentationMessage,
        challenge: Challenge,
        hasher: &mut impl Update,
    ) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        // TODO check revealed messages vs hidden message count on proof
        // TODO need to account for generators being 0?
        if generators.message_blinding_points_length()
            - self.hidden_message_count
            != rvl_msgs.len()
        {
            return Err(Error::BadParams {
                cause: format!(
                    "Incorrect number of revealed messages: #generators: {}, \
                     #hidden_messages: {}, #revealed_messages: {}",
                    generators.message_blinding_points_length(),
                    self.hidden_message_count,
                    rvl_msgs.len()
                ),
            });
        }

        // Validate the public key; it should not be an identity and should
        // belong to subgroup G2.
        if PK.is_valid().unwrap_u8() == 0 {
            return Err(Error::CryptoInvalidPublicKey);
        }

        // domain
        //  = hash_to_scalar((PK||L||generators||Ciphersuite_ID||header), 1)
        // TODO include Ciphersuite_ID
        let domain = compute_domain(PK, header, generators);

        // Adding data to hasher to calculate `cv` is done in many steps
        // whenever the data is ready
        // cv = hash_to_scalar((PK || Abar || A' || D || C1 || C2 || ph), 1)
        hasher.update(PK.to_bytes());
        hasher.update(self.A_bar.to_affine().to_uncompressed());
        hasher.update(self.A_prime.to_affine().to_uncompressed());
        hasher.update(self.D.to_affine().to_uncompressed());

        // C1 = (Abar - D) * c + A' * e^ + H_s * r2^
        let C1_points = [self.A_bar - self.D, self.A_prime, generators.H_s()];
        let C1_scalars = [challenge.0, self.proofs1[0].0, self.proofs1[1].0];
        let C1 = G1Projective::multi_exp(&C1_points, &C1_scalars);
        hasher.update(C1.to_affine().to_bytes());

        // T = P1 + H_s * domain + H_i1 * msg_i1 + ... H_iR * msg_iR
        let T_len = 1 + 1 + rvl_msgs.len();
        let mut T_points = Vec::with_capacity(T_len);
        let mut T_scalars = Vec::with_capacity(T_len);
        let P1 = G1Projective::generator();
        T_points.push(P1);
        T_scalars.push(Scalar::one());
        T_points.push(generators.H_d());
        T_scalars.push(domain);
        let mut revealed = HashSet::new();
        for (idx, msg) in rvl_msgs {
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
        let T = G1Projective::multi_exp(T_points.as_ref(), T_scalars.as_ref());

        // Compute C2 = T * c + D * (-r3^) + H_s * s^ +
        //           H_j1 * m^_j1 + ... + H_jU * m^_jU
        let C2_len = 1 + 1 + 1 + self.hidden_message_count;
        let mut C2_points = Vec::with_capacity(C2_len);
        let mut C2_scalars = Vec::with_capacity(C2_len);
        // T*c
        C2_points.push(T);
        C2_scalars.push(challenge.0);
        // D * (-r3^)
        C2_points.push(-self.D);
        C2_scalars.push(self.proofs2[0].0);
        // H_s * s^
        C2_points.push(generators.H_s());
        C2_scalars.push(self.proofs2[1].0);
        // H_j1 * m^_j1 + ... + H_jU * m^_jU
        let mut j = 2;
        for (i, generator) in
            generators.message_blinding_points_iter().enumerate()
        {
            if revealed.contains(&i) {
                continue;
            }
            C2_points.push(*generator);
            C2_scalars.push(self.proofs2[j].0);
            j += 1;
        }
        let C2 =
            G1Projective::multi_exp(C2_points.as_ref(), C2_scalars.as_ref());
        hasher.update(C2.to_affine().to_bytes());

        hasher.update(ph.to_bytes());

        Ok(())
    }

    /// Validate the proof, as defined in `ProofVerify` API in BBS Signature spec <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.7>,
    /// only checks the signature proof,
    /// the selective disclosure proof is checked by verifying
    /// `self.challenge == computed_challenge`.
    pub fn verify(&self, PK: PublicKey) -> bool {
        // Check the signature proof
        // if A' == 1, return INVALID
        if self.A_prime.is_identity().unwrap_u8() == 1 {
            return false;
        }

        // if e(A', W) * e(Abar, -P2) != 1, return INVALID
        // else return VALID
        let P2 = G2Affine::generator();
        Bls12::multi_miller_loop(&[
            (
                &self.A_prime.to_affine(),
                &G2Prepared::from(PK.0.to_affine()),
            ),
            (&self.A_bar.to_affine(), &G2Prepared::from(-P2)),
        ])
        .final_exponentiation()
        .is_identity()
        .unwrap_u8()
            == 1
    }
}

#[test]
fn serialization_test() {
    let p = PokSignatureProof {
        A_bar: G1Projective::generator(),
        A_prime: G1Projective::generator(),
        D: G1Projective::generator(),
        challenge: Challenge::default(),
        proofs1: [Challenge::default(), Challenge::default()],
        proofs2: vec![Challenge::default(), Challenge::default()],
        hidden_message_count: 0,
    };

    let bytes = p.to_bytes();
    let p2_opt = PokSignatureProof::from_bytes(&bytes);
    assert!(p2_opt.is_some());
    let p2 = p2_opt.unwrap();
    assert_eq!(p.A_bar, p2.A_bar);
    assert_eq!(p.A_prime, p2.A_prime);
    assert_eq!(p.D, p2.D);
    assert_eq!(p.hidden_message_count, p2.hidden_message_count);
}
