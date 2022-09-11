use super::ciphersuite::CipherSuiteId;
use crate::{
    curves::bls12_381::{G1Projective, G2Projective},
    Error,
};

pub(crate) trait HashToCurveParameter {
    /// Ciphersuite ID.
    const ID: CipherSuiteId;

    /// Default domain separation tag for `hash_to_point` operation in G1.
    fn default_hash_to_point_g1_dst() -> Vec<u8> {
        Self::ID.as_octets().to_vec()
    }

    /// Default domain separation tag for `hash_to_point` operation in G2.
    fn default_hash_to_point_g2_dst() -> Vec<u8> {
        Self::ID.as_octets().to_vec()
    }

    fn hash_to_g1(
        msg_octets: &[u8],
        dst: Option<&[u8]>,
    ) -> Result<G1Projective, Error>;

    fn hash_to_g2(
        msg_octets: &[u8],
        dst: Option<&[u8]>,
    ) -> Result<G2Projective, Error>;
}
