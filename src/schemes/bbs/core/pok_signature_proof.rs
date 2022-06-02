use super::{
    constants::{g1_affine_compressed_size, scalar_size},
    generator::Generators,
    public_key::PublicKey,
    types::{Challenge, Message},
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
    /// A' in section 4.5
    pub(crate) a_prime: G1Projective,
    /// \overline{A} in section 4.5
    pub(crate) a_bar: G1Projective,
    /// d in section 4.5
    pub(crate) d: G1Projective,
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

        buffer.extend_from_slice(&self.a_prime.to_affine().to_compressed());
        buffer.extend_from_slice(&self.a_bar.to_affine().to_compressed());
        buffer.extend_from_slice(&self.d.to_affine().to_compressed());
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
        let a_prime = G1Affine::from_compressed(slicer!(
            buffer,
            0,
            offset,
            Self::COMMITMENT_G1_BYTES
        ))
        .map(G1Projective::from);
        let a_bar = G1Affine::from_compressed(slicer!(
            buffer,
            offset,
            end,
            Self::COMMITMENT_G1_BYTES
        ))
        .map(G1Projective::from);
        offset = end;
        end = offset + Self::COMMITMENT_G1_BYTES;
        let d = G1Affine::from_compressed(slicer!(
            buffer,
            offset,
            end,
            Self::COMMITMENT_G1_BYTES
        ))
        .map(G1Projective::from);

        if a_prime.is_none().unwrap_u8() == 1
            || a_bar.is_none().unwrap_u8() == 1
            || d.is_none().unwrap_u8() == 1
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
            a_prime: a_prime.unwrap(),
            a_bar: a_bar.unwrap(),
            d: d.unwrap(),
            challenge: challenge.unwrap(),
            proofs1: [proofs1[0].unwrap(), proofs1[1].unwrap()],
            proofs2,
            hidden_message_count,
        })
    }

    /// Convert the committed values to bytes for the fiat-shamir challenge
    pub fn add_challenge_contribution(
        &self,
        generators: &Generators,
        rvl_msgs: &[(usize, Message)],
        challenge: Challenge,
        hasher: &mut impl Update,
    ) -> Result<(), Error> {
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

        hasher.update(self.a_prime.to_affine().to_uncompressed());
        hasher.update(self.a_bar.to_affine().to_uncompressed());
        hasher.update(self.d.to_affine().to_uncompressed());

        let proof1_points =
            [self.a_bar - self.d, self.a_prime, generators.H_s()];
        let proof1_scalars =
            [challenge.0, self.proofs1[0].0, self.proofs1[1].0];
        let commitment_proofs1 =
            G1Projective::multi_exp(&proof1_points, &proof1_scalars);
        hasher.update(commitment_proofs1.to_affine().to_bytes());

        let mut r_points = Vec::with_capacity(
            generators.message_blinding_points_length()
                - self.hidden_message_count,
        );
        let mut r_scalars = Vec::with_capacity(
            generators.message_blinding_points_length()
                - self.hidden_message_count,
        );

        r_points.push(G1Projective::generator());
        r_scalars.push(Scalar::one());

        let mut hidden = HashSet::new();
        for (idx, msg) in rvl_msgs {
            hidden.insert(*idx);
            if let Some(g) = generators.get_message_blinding_point(*idx) {
                r_points.push(g);
                r_scalars.push(msg.0);
            } else {
                // as we have already check about length, this should not happen
                return Err(Error::BadParams {
                    cause: "Generators out of range".to_owned(),
                });
            }
        }

        let r = G1Projective::multi_exp(r_points.as_ref(), r_scalars.as_ref());

        let mut proof2_points = Vec::with_capacity(
            3 + generators.message_blinding_points_length()
                - self.hidden_message_count,
        );
        let mut proof2_scalars = Vec::with_capacity(
            3 + generators.message_blinding_points_length()
                - self.hidden_message_count,
        );

        // r^c
        proof2_points.push(r);
        proof2_scalars.push(challenge.0);

        // d^-r3_hat
        proof2_points.push(-self.d);
        proof2_scalars.push(self.proofs2[0].0);

        // H_s^s_tick_hat
        proof2_points.push(generators.H_s());
        proof2_scalars.push(self.proofs2[1].0);

        let mut j = 2;
        for (i, generator) in
            generators.message_blinding_points_iter().enumerate()
        {
            if hidden.contains(&i) {
                continue;
            }
            proof2_points.push(*generator);
            proof2_scalars.push(self.proofs2[j].0);
            j += 1;
        }
        let commitment_proofs2 = G1Projective::multi_exp(
            proof2_points.as_ref(),
            proof2_scalars.as_ref(),
        );
        hasher.update(commitment_proofs2.to_affine().to_bytes());

        Ok(())
    }

    /// Validate the proof, only checks the signature proof
    /// the selective disclosure proof is checked by verifying
    /// self.challenge == computed_challenge
    pub fn verify(&self, public_key: PublicKey) -> bool {
        // check the signature proof
        if self.a_prime.is_identity().unwrap_u8() == 1 {
            return false;
        }
        Bls12::multi_miller_loop(&[
            (
                &self.a_prime.to_affine(),
                &G2Prepared::from(public_key.0.to_affine()),
            ),
            (
                &self.a_bar.to_affine(),
                &G2Prepared::from(-G2Affine::generator()),
            ),
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
        a_bar: G1Projective::generator(),
        a_prime: G1Projective::generator(),
        d: G1Projective::generator(),
        challenge: Challenge::default(),
        proofs1: [Challenge::default(), Challenge::default()],
        proofs2: vec![Challenge::default(), Challenge::default()],
        hidden_message_count: 0,
    };

    let bytes = p.to_bytes();
    let p2_opt = PokSignatureProof::from_bytes(&bytes);
    assert!(p2_opt.is_some());
    let p2 = p2_opt.unwrap();
    assert_eq!(p.a_bar, p2.a_bar);
    assert_eq!(p.a_prime, p2.a_prime);
    assert_eq!(p.d, p2.d);
    assert_eq!(p.hidden_message_count, p2.hidden_message_count);
}
