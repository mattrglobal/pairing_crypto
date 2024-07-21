use crate::{
    common::hash_param::h2c::HashToCurveParameter,
    curves::bls12_381::G1Projective,
};
use group::Group;

/// BLS-SIG BLS12-381 ciphersuites.
pub mod bls12_381;

/// BLS BLS12-381-G2-Shake-256-Aug ciphersuites.
pub mod bls12_381_g2_sha_256_aug;
/// BLS BLS12-381-G2-Shake-256-Nul ciphersuites.
pub mod bls12_381_g2_sha_256_nul;
/// BLS BLS12-381-G2-Shake-256-Pop ciphersuites.
pub mod bls12_381_g2_sha_256_pop;

pub(crate) trait BlsCiphersuiteParameters: HashToCurveParameter {
    /// Point on G1 to be used in signature and proof computation and
    /// verification.
    fn p1() -> G1Projective {
        G1Projective::generator()
    }
}

pub(crate) trait BlsSigAugCiphersuiteParameters:
    BlsCiphersuiteParameters
{
}
