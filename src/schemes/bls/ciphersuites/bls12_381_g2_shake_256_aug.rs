use crate::{
    common::{ciphersuite::CipherSuiteId, h2c::HashToCurveParameter},
    curves::bls12_381::{
        hash_to_curve::ExpandMsgXof,
        G1Projective,
        G2Projective,
    },
    Error,
};
use sha3::Shake256;

pub(crate) struct Bls12381G2XofShake256AugCipherSuiteParameter;

impl<'a> HashToCurveParameter for Bls12381G2XofShake256AugCipherSuiteParameter {
    const ID: CipherSuiteId = CipherSuiteId::BlsSigBls12381G2XofShake256Aug;

    fn hash_to_g1(
        msg_octets: &[u8],
        dst: Option<&[u8]>,
    ) -> Result<blstrs::G1Projective, Error> {
        let default_dst = Self::default_hash_to_point_g1_dst();
        let dst_octets = dst.unwrap_or(&default_dst);

        Ok(G1Projective::hash_to::<ExpandMsgXof<Shake256>>(
            &msg_octets,
            dst_octets,
        ))
    }

    fn hash_to_g2(
        msg_octets: &[u8],
        dst: Option<&[u8]>,
    ) -> Result<blstrs::G2Projective, Error> {
        let default_dst = Self::default_hash_to_point_g1_dst();
        let dst_octets = dst.unwrap_or(&default_dst);

        Ok(G2Projective::hash_to::<ExpandMsgXof<Shake256>>(
            &msg_octets,
            dst_octets,
        ))
    }
}
