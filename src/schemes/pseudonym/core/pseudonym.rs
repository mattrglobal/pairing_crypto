#![allow(dead_code)]
#![allow(unused)]
#![allow(non_snake_case)]
use crate::{
    bbs::interface::BbsInterfaceParameter,
    curves::{
        bls12_381::{G1Projective, Scalar, OCTET_POINT_G1_LENGTH},
        point_serde::{octets_to_point_g1, point_to_octets_g1},
    },
    error::Error,
    schemes::bbs::ciphersuites::BbsCiphersuiteParameters,
};
use ff::Field;
use group::Group;
pub(crate) struct Pseudonym(G1Projective);

// TODO: Use ct to check equalities bellow
impl Pseudonym {
    pub fn new<T, I>(
        verifier_id: &T,
        prover_id: &T,
        api_id: Option<Vec<u8>>,
    ) -> Result<Self, Error>
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

        let api_id = api_id.as_ref().map_or(&[] as &[u8], |v| v.as_ref());
        let OP = I::Ciphersuite::hash_to_curve(verifier_id, api_id)?;

        // Check that OP is not the identity, the base point of G1 or P1.
        if OP.is_identity().unwrap_u8() == 1u8
            || OP == G1Projective::generator()
            || OP == I::Ciphersuite::p1().unwrap()
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
            || pid_scalar == Scalar::one()
        {
            return Err(Error::CryptoOps {
                cause: "Invalid Prover ID after is mapped to a scalar"
                    .to_owned(),
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
}
