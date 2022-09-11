use crate::{
    common::h2c::HashToCurveParameter,
    curves::bls12_381::{G1Projective, G2Projective},
};
use group::Group;

/// BLS-SIG BLS12-381 ciphersuites.
pub mod bls12_381;
/// BLS BLS12-381-G2-Shake-256-Aug ciphersuites.
pub mod bls12_381_g2_shake_256_aug;

pub(crate) trait BlsCiphersuiteParameters<'a>:
    HashToCurveParameter
{
    /// Point on G1 to be used in signature and proof computation and
    /// verification.
    fn p1() -> G1Projective {
        G1Projective::generator()
    }

    /// Point on G2 to be used during signature and proof verification.
    fn p2() -> G2Projective {
        G2Projective::generator()
    }
}
