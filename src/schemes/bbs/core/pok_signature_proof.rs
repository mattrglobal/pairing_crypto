#![allow(non_snake_case)]

use super::{
    constants::{g1_affine_compressed_size, scalar_size},
    generator::Generators,
    public_key::PublicKey,
    types::{Challenge, Message, PresentationMessage},
    utils::{compute_domain, octets_to_point_g1, point_to_octets_g1},
};
use crate::{
    curves::bls12_381::{Bls12, G1Projective, G2Affine, G2Prepared, Scalar},
    error::Error,
};
use core::convert::TryFrom;
use digest::Update;
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve, Group};
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
/// Contains the proof of 2 discrete log relations.
/// The `ProofGen` procedure is specified here <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofgen>
/// proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1, ..., m^_jU))
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
    pub(crate) c: Challenge,
    pub(crate) hidden_message_count: usize,
}

impl PokSignatureProof {
    const FIELD_BYTES: usize = scalar_size();
    const COMMITMENT_G1_BYTES: usize = g1_affine_compressed_size();

    // Number of fixed secret points in proof2 or commitment2 vector are `r3`
    // and `s'`.
    const NUM_PROOF2_FIXED_POINTS: usize = 2;

    /// Store the proof as a sequence of bytes in big endian format.
    /// Each point is serialized to big-endian format.
    /// Needs G1_COMPRESSED_SIZE * 3 + SCALAR_SIZE * (5 + U) space where
    ///     G1_COMPRESSED_SIZE, size of a point in G1 in compressed form,
    ///     SCALAR_SIZE, size of a `Scalar`, and
    ///     U is the number of hidden messages.
    /// For BLS12-381 based implementation, G1_COMPRESSED_SIZE is 48 byes, and
    /// SCALAR_SIZE is 32 bytes, then
    /// proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_1, ..., m^_U))
    /// bytes sequence will be [48, 48, 48, 32, 32, 32, 32, 32, 32*U ].
    pub fn to_octets(&self) -> Vec<u8> {
        // self.proofs2.len() contains 2 fixed scalars r3^, s^, and U variable
        // scalars.
        let size = Self::COMMITMENT_G1_BYTES * 3
            + Self::FIELD_BYTES * (1 + 2 + self.proofs2.len());

        let mut buffer = Vec::with_capacity(size);

        // proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1, ..., m^_jU))
        buffer.extend_from_slice(&point_to_octets_g1(&self.A_prime));
        buffer.extend_from_slice(&point_to_octets_g1(&self.A_bar));
        buffer.extend_from_slice(&point_to_octets_g1(&self.D));
        buffer.extend_from_slice(&self.c.to_bytes());
        for i in 0..self.proofs1.len() {
            buffer.extend_from_slice(&self.proofs1[i].to_bytes());
        }
        for i in 0..self.proofs2.len() {
            buffer.extend_from_slice(&self.proofs2[i].to_bytes());
        }
        buffer
    }

    /// Get the proof `PokSignatureProof` from a sequence of bytes in big endian
    /// format. Each member of `PokSignatureProof` is deserialized from
    /// big-endian bytes.
    /// Expected input size is G1_COMPRESSED_SIZE * 3 + SCALAR_SIZE * (5 + U)
    /// where
    ///      G1_COMPRESSED_SIZE, size of a point in G1 in ompressed form,
    ///      SCALAR_SIZE, size of a `Scalar`, and
    ///      U is the number of hidden messages.
    /// For BLS12-381 based implementation, G1_COMPRESSED_SIZE is 48 byes, and
    /// SCALAR_SIZE is 32 bytes, then bytes sequence will be treated as
    /// [48, 48, 48, 32, 32, 32, 32, 32, 32*U ] to represent   
    /// proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_1, ..., m^_U)).
    pub fn from_octets<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        let size = Self::COMMITMENT_G1_BYTES * 3 + Self::FIELD_BYTES * 5;
        let buffer = bytes.as_ref();
        if buffer.len() < size {
            return Err(Error::CryptoMalformedProof {
                cause: format!(
                    "not enough data, input buffer size: {} bytes",
                    buffer.len()
                ),
            });
        }
        if (buffer.len() - Self::COMMITMENT_G1_BYTES) % Self::FIELD_BYTES != 0 {
            return Err(Error::CryptoMalformedProof {
                cause: format!(
                    "variable length data {} is not multiple of `Scalar` size \
                     {} bytes",
                    buffer.len() - Self::COMMITMENT_G1_BYTES,
                    Self::FIELD_BYTES
                ),
            });
        }

        // In near future update of spec, length will be encoded as per https://github.com/decentralized-identity/bbs-signature/pull/155/
        // TODO update this once above PR is merged in spec.
        let hidden_message_count = (buffer.len() - size) / Self::FIELD_BYTES;

        let mut offset = 0usize;
        let mut end = Self::COMMITMENT_G1_BYTES;

        // Get A_prime, A_bar, and D
        let A_prime = octets_to_point_g1(slicer!(
            buffer,
            offset,
            end,
            Self::COMMITMENT_G1_BYTES
        ))?;
        offset = end;
        if A_prime.is_identity().unwrap_u8() == 1 {
            return Err(Error::CryptoPointIsIdentity);
        }

        // Get A_bar
        end += Self::COMMITMENT_G1_BYTES;
        let A_bar = octets_to_point_g1(slicer!(
            buffer,
            offset,
            end,
            Self::COMMITMENT_G1_BYTES
        ))?;
        offset = end;
        if A_bar.is_identity().unwrap_u8() == 1 {
            return Err(Error::CryptoPointIsIdentity);
        }

        // Get D
        end += Self::COMMITMENT_G1_BYTES;
        let D = octets_to_point_g1(slicer!(
            buffer,
            offset,
            end,
            Self::COMMITMENT_G1_BYTES
        ))?;
        if D.is_identity().unwrap_u8() == 1 {
            return Err(Error::CryptoPointIsIdentity);
        }

        // Get c
        offset = end;
        end = offset + Self::FIELD_BYTES;
        let c = Challenge::from_bytes(slicer!(
            buffer,
            offset,
            end,
            Self::FIELD_BYTES
        ));
        if c.is_none().unwrap_u8() == 1 {
            return Err(Error::CryptoMalformedProof {
                cause: "failure while deserializing `c`".to_owned(),
            });
        }

        // Get e^, r2^
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
            return Err(Error::CryptoMalformedProof {
                cause: "failure while deserializing `e^` or `r2^`".to_owned(),
            });
        }

        let mut proofs2 =
            Vec::<Challenge>::with_capacity(2 + hidden_message_count);
        for _ in 0..(2 + hidden_message_count) {
            let c = Challenge::from_bytes(slicer!(
                buffer,
                offset,
                end,
                Self::FIELD_BYTES
            ));
            offset = end;
            end = offset + Self::FIELD_BYTES;
            if c.is_none().unwrap_u8() == 1 {
                return Err(Error::CryptoMalformedProof {
                    cause: "failure while deserializing `proof2` components"
                        .to_owned(),
                });
            }

            proofs2.push(c.unwrap());
        }

        // It's safe to `unwrap()` here as we have already handled the `None`
        // case above.
        Ok(Self {
            A_prime,
            A_bar,
            D,
            c: c.unwrap(),
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
        header: Option<T>,
        generators: &Generators,
        rvl_msgs: &[(usize, Message)],
        ph: Option<PresentationMessage>,
        challenge: Challenge,
        hasher: &mut impl Update,
    ) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        // Input parameter checks
        if self.hidden_message_count + rvl_msgs.len()
            != generators.message_blinding_points_length()
        {
            return Err(Error::BadParams {
                cause: format!(
                    "Incorrect number of messages and generators: \
                     [#generators: {}, #hidden_messages: {}, \
                     #revealed_messages: {}]",
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
        let domain = compute_domain(
            PK,
            header,
            generators.message_blinding_points_length(),
            generators,
        )?;

        // C1 = (Abar - D) * c + A' * e^ + H_s * r2^
        let C1_points = [self.A_bar - self.D, self.A_prime, generators.H_s()];
        let C1_scalars = [challenge.0, self.proofs1[0].0, self.proofs1[1].0];
        let C1 = G1Projective::multi_exp(&C1_points, &C1_scalars);

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
        let mut j = Self::NUM_PROOF2_FIXED_POINTS;
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

        // cv = hash_to_scalar((PK || Abar || A' || D || C1 || C2 || ph), 1)
        hasher.update(PK.point_to_octets());
        hasher.update(point_to_octets_g1(&self.A_bar));
        hasher.update(point_to_octets_g1(&self.A_prime));
        hasher.update(point_to_octets_g1(&self.D));
        hasher.update(point_to_octets_g1(&C1));
        hasher.update(point_to_octets_g1(&C2));
        if let Some(ph) = ph {
            hasher.update(ph.to_bytes());
        }
        Ok(())
    }

    /// Validate the proof, as defined in `ProofVerify` API in BBS Signature spec <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#section-3.3.7>,
    /// only checks the signature proof, the selective disclosure proof is
    /// checked by verifying `self.challenge == computed_challenge`.
    pub fn verify_signature_proof(&self, PK: PublicKey) -> Result<bool, Error> {
        // Check the signature proof
        // if A' == 1, return INVALID
        if self.A_prime.is_identity().unwrap_u8() == 1 {
            return Err(Error::CryptoPointIsIdentity);
        }

        // if e(A', W) * e(Abar, -P2) != 1, return INVALID
        // else return VALID
        let P2 = G2Affine::generator();
        Ok(Bls12::multi_miller_loop(&[
            (
                &self.A_prime.to_affine(),
                &G2Prepared::from(PK.0.to_affine()),
            ),
            (&self.A_bar.to_affine(), &G2Prepared::from(-P2)),
        ])
        .final_exponentiation()
        .is_identity()
        .unwrap_u8()
            == 1)
    }
}

#[test]
fn serialization_test() {
    let p = PokSignatureProof {
        A_bar: G1Projective::generator(),
        A_prime: G1Projective::generator(),
        D: G1Projective::generator(),
        c: Challenge::default(),
        proofs1: [Challenge::default(), Challenge::default()],
        proofs2: vec![Challenge::default(), Challenge::default()],
        hidden_message_count: 0,
    };

    let bytes = p.to_octets();
    let p2_opt = PokSignatureProof::from_octets(&bytes);
    assert!(p2_opt.is_ok());
    let p2 = p2_opt.unwrap();
    assert_eq!(p.A_bar, p2.A_bar);
    assert_eq!(p.A_prime, p2.A_prime);
    assert_eq!(p.D, p2.D);
    assert_eq!(p.hidden_message_count, p2.hidden_message_count);
}
