use super::SecretKey;
use crate::core::*;
use bls12_381_plus::{G1Projective, Scalar};
use core::convert::TryFrom;
use digest::{ExtendableOutput, Update, XofReader};
use group::{Curve, GroupEncoding};
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use sha3::Shake256;
use subtle::ConstantTimeEq;

/// Contains the data used for computing a blind signature and verifying
/// proof of hidden messages from a prover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSignatureContext {
    /// The blinded signature commitment
    pub commitment: Commitment,
    /// The challenge hash for the Fiat-Shamir heuristic
    pub challenge: Challenge,
    /// The proofs for the hidden messages
    pub proofs: Vec<Challenge>,
}

impl BlindSignatureContext {
    /// Store the generators as a sequence of bytes
    /// Each point is compressed to big-endian format
    /// Needs (N + 1) * 32 + 48 * 2 space otherwise it will panic
    pub fn to_bytes(&self, buffer: &mut [u8]) {
        buffer[0..COMMITMENT_G1_BYTES].copy_from_slice(&self.commitment.to_bytes());
        let mut offset = COMMITMENT_G1_BYTES;
        let mut end = offset + FIELD_BYTES;

        buffer[offset..end].copy_from_slice(&self.challenge.to_bytes());

        offset = end;
        end += FIELD_BYTES;

        for i in 0..self.proofs.len() {
            buffer[offset..end].copy_from_slice(&self.proofs[i].to_bytes());
            offset = end;
            end += FIELD_BYTES;
        }
    }

    /// Convert a byte sequence into the blind signature context
    /// Expected size is (N + 1) * 32 + 48 bytes
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        let size = FIELD_BYTES * 2 + COMMITMENT_G1_BYTES;
        let buffer = bytes.as_ref();
        if buffer.len() < size {
            return None;
        }
        if buffer.len() - COMMITMENT_G1_BYTES % FIELD_BYTES != 0 {
            return None;
        }

        let commitment =
            Commitment::from_bytes(slicer!(buffer, 0, COMMITMENT_G1_BYTES, COMMITMENT_G1_BYTES));
        if commitment.is_none().unwrap_u8() == 1 {
            return None;
        }
        let mut offset = COMMITMENT_G1_BYTES;
        let mut end = COMMITMENT_G1_BYTES + FIELD_BYTES;

        let challenge = Challenge::from_bytes(slicer!(buffer, offset, end, FIELD_BYTES));
        if challenge.is_none().unwrap_u8() == 1 {
            return None;
        }

        let times = (buffer.len() - COMMITMENT_G1_BYTES - FIELD_BYTES) / FIELD_BYTES;

        offset = end;
        end += FIELD_BYTES;

        let mut proofs = Vec::with_capacity(times);
        for _ in 0..times {
            let p = Challenge::from_bytes(slicer!(buffer, offset, end, FIELD_BYTES));
            if p.is_none().unwrap_u8() == 1 {
                return None;
            }
            proofs.push(p.unwrap());
            offset = end;
            end += FIELD_BYTES;
        }

        Some(Self {
            commitment: commitment.unwrap(),
            challenge: challenge.unwrap(),
            proofs,
        })
    }

    /// Assumes the proof of hidden messages
    /// If other proofs were included, those will need to be verified another way
    pub fn verify(
        &self,
        known_messages: &[usize],
        sk: &SecretKey,
        nonce: Nonce,
    ) -> Result<bool, Error> {
        let mut known = HashSet::new();
        let mut points = Vec::with_capacity(2 + sk.y.len() - known.len());
        for idx in known_messages {
            if *idx >= sk.y.len() {
                return Err(Error::new(1, "index out of bounds"));
            }
            known.insert(*idx);
        }
        for i in 0..sk.y.len() {
            if !known.contains(&i) {
                points.push(G1Projective::generator() * sk.y[i]);
            }
        }
        points.push(G1Projective::generator());
        points.push(self.commitment.0);

        let mut scalars: Vec<_> = self.proofs.iter().map(|p| p.0).collect();
        scalars.push(-self.challenge.0);

        let mut res = [0u8; COMMITMENT_G1_BYTES];
        let mut hasher = Shake256::default();

        let commitment = G1Projective::sum_of_products_in_place(points.as_ref(), scalars.as_mut());
        hasher.update(&commitment.to_affine().to_bytes());
        hasher.update(&self.commitment.0.to_affine().to_uncompressed());
        hasher.update(nonce.to_bytes());
        let mut reader = hasher.finalize_xof();
        reader.read(&mut res);
        let challenge = Scalar::from_okm(&res);

        Ok(self.challenge.0.ct_eq(&challenge).unwrap_u8() == 1)
    }
}
