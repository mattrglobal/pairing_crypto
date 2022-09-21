use super::ciphersuite::CipherSuiteParameter;
use crate::{
    curves::bls12_381::{G1Projective, G2Projective},
    Error,
};
use core::fmt::Debug;

pub(crate) trait HashToCurveParameter:
    Debug + Clone + CipherSuiteParameter
{
    /// Default domain separation tag for `hash_to_point` operation.
    fn default_hash_to_point_dst() -> Vec<u8> {
        Self::ID.as_octets().to_vec()
    }

    fn hash_to_g1(message: &[u8], dst: &[u8]) -> Result<G1Projective, Error>;

    fn hash_to_g2(message: &[u8], dst: &[u8]) -> Result<G2Projective, Error>;
}
