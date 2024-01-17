#![allow(non_snake_case)]

use crate::{
    bbs::{
        ciphersuites::BbsCiphersuiteParameters,
        interface::BbsInterfaceParameter,
    },
    curves::{
        bls12_381::{G1Projective, Scalar, OCTET_POINT_G1_LENGTH},
        point_serde::{octets_to_point_g1, point_to_octets_g1},
    },
    error::Error,
};
use ff::Field;
use group::{Curve, Group};
use subtle::{Choice, ConstantTimeEq};

pub(crate) struct Pseudonym(G1Projective);

// TODO: Use ct to check equalities bellow
impl Pseudonym {
    pub fn new<T, I>(verifier_id: &T, prover_id: &T) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
        I: BbsInterfaceParameter,
    {
        // Check that Verifier ID and Prover ID are not empty.
        let verifier_id = verifier_id.as_ref();
        let prover_id = prover_id.as_ref();

        if verifier_id.is_empty() || prover_id.is_empty() {
            return Err(Error::BadParams {
                cause: "Both the Verifier and the Prover Identifiers must be \
                        non empty"
                    .to_owned(),
            });
        }

        let OP = I::hash_to_curve(verifier_id)?;

        // Check that OP is not the identity, the base point of G1 or P1.
        if OP.is_identity().unwrap_u8() == 1u8
            || OP.ct_eq(&G1Projective::generator()).unwrap_u8() == 1u8
            || OP.ct_eq(&I::Ciphersuite::p1().unwrap()).unwrap_u8() == 1u8
        {
            return Err(Error::CryptoOps {
                cause: "Origin defined point of G1 must not be the Identity, \
                        the Base point or the P1 point of the ciphersuite"
                    .to_owned(),
            });
        }

        let pid_scalar = I::map_message_to_scalar_as_hash(
            prover_id, None, // Use the default dst
        )?;

        if pid_scalar.is_zero().unwrap_u8() == 1u8
            || pid_scalar.ct_eq(&Scalar::one()).unwrap_u8() == 1u8
        {
            return Err(Error::CryptoOps {
                cause: "Invalid Prover ID".to_owned(),
            });
        };

        Ok(Self(OP * pid_scalar))
    }

    pub fn as_point(&self) -> G1Projective {
        self.0
    }

    pub fn to_octets(&self) -> [u8; OCTET_POINT_G1_LENGTH] {
        point_to_octets_g1(&self.0)
    }

    pub fn from_octets(
        bytes: &[u8; OCTET_POINT_G1_LENGTH],
    ) -> Result<Self, Error> {
        let point = octets_to_point_g1(bytes)?;
        Ok(Self(point))
    }

    pub fn is_valid<C>(&self) -> Choice
    where
        C: BbsCiphersuiteParameters,
    {
        (!self.0.is_identity())
            & self.0.is_on_curve()
            & self.0.to_affine().is_torsion_free()
            & !(Choice::from((self.0 == G1Projective::generator()) as u8))
            & !(Choice::from((self.0 == C::p1().unwrap()) as u8))
    }
}
