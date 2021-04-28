use super::MessageGenerators;
use crate::curves::bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, Scalar,
};
use crate::schemes::bls::PublicKey;
use crate::schemes::core::*;
use core::convert::TryFrom;
use digest::Update;
use group::{Curve, Group, GroupEncoding};
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use subtle::{Choice, CtOption};

/// The actual proof that is sent from prover to verifier.
///
/// Contains the proof of 2 discrete log relations.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PokSignatureProof {
    pub(crate) a_prime: G1Projective,
    pub(crate) a_bar: G1Projective,
    pub(crate) d: G1Projective,
    pub(crate) proofs1: [Challenge; 2],
    pub(crate) proofs2: Vec<Challenge>,
}

impl PokSignatureProof {
    /// Store the proof as a sequence of bytes
    /// Each point is compressed to big-endian format
    /// Needs (N + 2) * 32 + 48 * 3 space otherwise it will panic
    /// where N is the number of hidden messages
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = FIELD_BYTES * (2 + self.proofs2.len()) + COMMITMENT_G1_BYTES * 3;
        let mut buffer = Vec::with_capacity(size);

        buffer.extend_from_slice(&self.a_prime.to_affine().to_compressed());
        buffer.extend_from_slice(&self.a_bar.to_affine().to_compressed());
        buffer.extend_from_slice(&self.d.to_affine().to_compressed());

        for i in 0..self.proofs1.len() {
            buffer.extend_from_slice(&self.proofs1[i].to_bytes());
        }
        for i in 0..self.proofs2.len() {
            buffer.extend_from_slice(&self.proofs2[i].to_bytes());
        }
        buffer
    }

    /// Convert a byte sequence into the blind signature context
    /// Expected size is (N + 1) * 32 + 48 bytes
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        let size = FIELD_BYTES * 4 + COMMITMENT_G1_BYTES * 3;
        let buffer = bytes.as_ref();
        if buffer.len() < size {
            return None;
        }
        if buffer.len() - COMMITMENT_G1_BYTES % FIELD_BYTES != 0 {
            return None;
        }

        let hid_msg_cnt = (buffer.len() - size) / FIELD_BYTES;
        let mut offset = COMMITMENT_G1_BYTES;
        let mut end = COMMITMENT_G1_BYTES + FIELD_BYTES;
        let a_prime = G1Affine::from_compressed(slicer!(buffer, 0, offset, COMMITMENT_G1_BYTES))
            .map(G1Projective::from);
        let a_bar = G1Affine::from_compressed(slicer!(buffer, offset, end, COMMITMENT_G1_BYTES))
            .map(G1Projective::from);
        offset = end;
        end = offset + COMMITMENT_G1_BYTES;
        let d = G1Affine::from_compressed(slicer!(buffer, offset, end, COMMITMENT_G1_BYTES))
            .map(G1Projective::from);

        if a_prime.is_none().unwrap_u8() == 1
            || a_bar.is_none().unwrap_u8() == 1
            || d.is_none().unwrap_u8() == 1
        {
            return None;
        }

        offset = end;
        end = offset + FIELD_BYTES;

        let mut proofs1 = [
            CtOption::new(Challenge::default(), Choice::from(0u8)),
            CtOption::new(Challenge::default(), Choice::from(0u8)),
        ];
        for proof in &mut proofs1 {
            *proof = Challenge::from_bytes(slicer!(buffer, offset, end, FIELD_BYTES));
            offset = end;
            end = offset + FIELD_BYTES;
        }
        if proofs1[0].is_none().unwrap_u8() == 1 || proofs1[1].is_none().unwrap_u8() == 1 {
            return None;
        }

        let mut proofs2 = Vec::<Challenge>::with_capacity(hid_msg_cnt + 2);
        for _ in 0..(hid_msg_cnt + 2) {
            let c = Challenge::from_bytes(slicer!(buffer, offset, end, FIELD_BYTES));
            offset = end;
            end = offset + FIELD_BYTES;
            if c.is_none().unwrap_u8() == 1 {
                return None;
            }

            proofs2.push(c.unwrap());
        }
        Some(Self {
            a_prime: a_prime.unwrap(),
            a_bar: a_bar.unwrap(),
            d: d.unwrap(),
            proofs1: [proofs1[0].unwrap(), proofs1[1].unwrap()],
            proofs2,
        })
    }

    /// Convert the committed values to bytes for the fiat-shamir challenge
    pub fn add_challenge_contribution(
        &self,
        generators: &MessageGenerators,
        rvl_msgs: &[(usize, Message)],
        challenge: Challenge,
        hasher: &mut impl Update,
    ) {
        hasher.update(self.a_prime.to_affine().to_uncompressed());
        hasher.update(self.a_bar.to_affine().to_uncompressed());
        hasher.update(self.d.to_affine().to_uncompressed());

        let proof1_points = [self.a_bar - self.d, self.a_prime, generators.h0];
        let mut proof1_scalars = [challenge.0, self.proofs1[0].0, self.proofs1[1].0];
        let commitment_proofs1 =
            G1Projective::sum_of_products_in_place(&proof1_points, &mut proof1_scalars);
        hasher.update(commitment_proofs1.to_affine().to_bytes());

        let mut r_points = Vec::with_capacity(1 + rvl_msgs.len());
        let mut r_scalars = Vec::with_capacity(1 + rvl_msgs.len());

        r_points.push(G1Projective::generator());
        r_scalars.push(Scalar::one());

        let mut hidden = HashSet::new();
        for (idx, msg) in rvl_msgs {
            hidden.insert(*idx);
            r_points.push(generators.get(*idx));
            r_scalars.push(msg.0);
        }

        let r = G1Projective::sum_of_products_in_place(r_points.as_ref(), r_scalars.as_mut());

        let mut proof2_points = Vec::with_capacity(3 + generators.len() - hidden.len());
        let mut proof2_scalars = Vec::with_capacity(3 + generators.len() - hidden.len());

        // r^c
        proof2_points.push(r);
        proof2_scalars.push(challenge.0);

        // d^-r3_hat
        proof2_points.push(-self.d);
        proof2_scalars.push(self.proofs2[0].0);

        // h0^s_tick_hat
        proof2_points.push(generators.h0);
        proof2_scalars.push(self.proofs2[1].0);

        let mut j = 2;
        for i in 0..generators.len() {
            if hidden.contains(&i) {
                continue;
            }
            proof2_points.push(generators.get(i));
            proof2_scalars.push(self.proofs2[j].0);
            j += 1;
        }
        let commitment_proofs2 =
            G1Projective::sum_of_products_in_place(proof2_points.as_ref(), proof2_scalars.as_mut());
        hasher.update(commitment_proofs2.to_affine().to_bytes());
    }

    /// Validate the proof, only checks the signature proof
    /// the selective disclosure proof is checked by verifying
    /// self.challenge == computed_challenge
    pub fn verify(&self, public_key: PublicKey) -> bool {
        // check the signature proof
        if self.a_prime.is_identity().unwrap_u8() == 1 {
            return false;
        }
        multi_miller_loop(&[
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
