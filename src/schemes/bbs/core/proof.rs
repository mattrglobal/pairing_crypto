#![allow(non_snake_case)]

use super::{
    constants::{OCTET_POINT_G1_LENGTH, OCTET_SCALAR_LENGTH},
    types::Challenge,
    utils::{octets_to_point_g1, point_to_octets_g1},
};
use crate::{curves::bls12_381::G1Projective, error::Error};
use core::convert::TryFrom;
use group::Group;
use subtle::{Choice, CtOption};

// Convert slice to a fixed array
macro_rules! slicer {
    ($d:expr, $b:expr, $e:expr, $s:expr) => {
        &<[u8; $s]>::try_from(&$d[$b..$e]).unwrap()
    };
}

/// The zero-knowledge proof-of-knowledge of a signature that is sent from
/// prover to verifier. Contains the proof of 2 discrete log relations.
/// The `ProofGen` procedure is specified here <https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-proofgen>
/// proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_1, ..., m^_U)), where `U` is
/// number of unrevealed messages.
#[derive(Debug, Clone)]
pub struct Proof {
    /// A'
    pub(crate) A_prime: G1Projective,
    /// \overline{A}
    pub(crate) A_bar: G1Projective,
    /// D
    pub(crate) D: G1Projective,
    /// c
    pub(crate) c: Challenge,
    /// e^, r2^
    pub(crate) C1_scalars: [Challenge; 2],
    /// r3^, s^, (m^_1, ..., m^_U)
    pub(crate) C2_scalars: Vec<Challenge>,
}

impl Proof {
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
        // self.C2_scalars.len() contains 2 fixed scalars r3^, s^, and U
        // variable scalars.
        let size = OCTET_POINT_G1_LENGTH * 3
            + OCTET_SCALAR_LENGTH * (1 + 2 + self.C2_scalars.len());

        let mut buffer = Vec::with_capacity(size);

        // proof = (A', Abar, D, c, e^, r2^, r3^, s^, (m^_j1, ..., m^_jU))
        buffer.extend_from_slice(&point_to_octets_g1(&self.A_prime));
        buffer.extend_from_slice(&point_to_octets_g1(&self.A_bar));
        buffer.extend_from_slice(&point_to_octets_g1(&self.D));
        buffer.extend_from_slice(&self.c.to_bytes());
        for i in 0..self.C1_scalars.len() {
            buffer.extend_from_slice(&self.C1_scalars[i].to_bytes());
        }
        for i in 0..self.C2_scalars.len() {
            buffer.extend_from_slice(&self.C2_scalars[i].to_bytes());
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
            return Err(Error::CryptoMalformedProof {
                cause: format!(
                    "not enough data, input buffer size: {} bytes",
                    buffer.len()
                ),
            });
        }
        if (buffer.len() - OCTET_POINT_G1_LENGTH) % OCTET_SCALAR_LENGTH != 0 {
            return Err(Error::CryptoMalformedProof {
                cause: format!(
                    "variable length data {} is not multiple of `Scalar` size \
                     {} bytes",
                    buffer.len() - OCTET_POINT_G1_LENGTH,
                    OCTET_SCALAR_LENGTH
                ),
            });
        }

        let hidden_message_count =
            (buffer.len() - PROOF_LEN_FLOOR) / OCTET_SCALAR_LENGTH;

        let mut offset = 0usize;
        let mut end = OCTET_POINT_G1_LENGTH;

        // Get A_prime
        let A_prime = octets_to_point_g1(slicer!(
            buffer,
            offset,
            end,
            OCTET_POINT_G1_LENGTH
        ))?;
        if A_prime.is_identity().unwrap_u8() == 1 {
            return Err(Error::CryptoPointIsIdentity);
        }
        offset = end;

        // Get A_bar
        end += OCTET_POINT_G1_LENGTH;
        let A_bar = octets_to_point_g1(slicer!(
            buffer,
            offset,
            end,
            OCTET_POINT_G1_LENGTH
        ))?;
        if A_bar.is_identity().unwrap_u8() == 1 {
            return Err(Error::CryptoPointIsIdentity);
        }
        offset = end;

        // Get D
        end += OCTET_POINT_G1_LENGTH;
        let D = octets_to_point_g1(slicer!(
            buffer,
            offset,
            end,
            OCTET_POINT_G1_LENGTH
        ))?;
        if D.is_identity().unwrap_u8() == 1 {
            return Err(Error::CryptoPointIsIdentity);
        }
        offset = end;

        // Get c
        end = offset + OCTET_SCALAR_LENGTH;
        let c = Challenge::from_bytes(slicer!(
            buffer,
            offset,
            end,
            OCTET_SCALAR_LENGTH
        ));
        if c.is_none().unwrap_u8() == 1 {
            return Err(Error::CryptoMalformedProof {
                cause: "failure while deserializing `c`".to_owned(),
            });
        }
        offset = end;

        // Get e^, r2^
        end = offset + OCTET_SCALAR_LENGTH;
        let mut C1_scalars = [
            CtOption::new(Challenge::default(), Choice::from(0u8)),
            CtOption::new(Challenge::default(), Choice::from(0u8)),
        ];
        for proof in &mut C1_scalars {
            *proof = Challenge::from_bytes(slicer!(
                buffer,
                offset,
                end,
                OCTET_SCALAR_LENGTH
            ));
            offset = end;
            end = offset + OCTET_SCALAR_LENGTH;
        }
        if C1_scalars[0].is_none().unwrap_u8() == 1
            || C1_scalars[1].is_none().unwrap_u8() == 1
        {
            return Err(Error::CryptoMalformedProof {
                cause: "failure while deserializing `e^` or `r2^`".to_owned(),
            });
        }

        let mut C2_scalars =
            Vec::<Challenge>::with_capacity(2 + hidden_message_count);
        for _ in 0..(2 + hidden_message_count) {
            let c = Challenge::from_bytes(slicer!(
                buffer,
                offset,
                end,
                OCTET_SCALAR_LENGTH
            ));
            offset = end;
            end = offset + OCTET_SCALAR_LENGTH;
            if c.is_none().unwrap_u8() == 1 {
                return Err(Error::CryptoMalformedProof {
                    cause: "failure while deserializing `proof2` components"
                        .to_owned(),
                });
            }

            C2_scalars.push(c.unwrap());
        }

        // It's safe to `unwrap()` here as we have already handled the `None`
        // case above.
        Ok(Self {
            A_prime,
            A_bar,
            D,
            c: c.unwrap(),
            C1_scalars: [C1_scalars[0].unwrap(), C1_scalars[1].unwrap()],
            C2_scalars,
        })
    }
}

#[test]
fn serialization_test() {
    let p = Proof {
        A_bar: G1Projective::generator(),
        A_prime: G1Projective::generator(),
        D: G1Projective::generator(),
        c: Challenge::default(),
        C1_scalars: [Challenge::default(), Challenge::default()],
        C2_scalars: vec![Challenge::default(), Challenge::default()],
    };

    let bytes = p.to_octets();
    let p2_opt = Proof::from_octets(&bytes);
    assert!(p2_opt.is_ok());
    let p2 = p2_opt.unwrap();
    assert_eq!(p.A_bar, p2.A_bar);
    assert_eq!(p.A_prime, p2.A_prime);
    assert_eq!(p.D, p2.D);
}
