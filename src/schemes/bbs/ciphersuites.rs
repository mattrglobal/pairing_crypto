use crate::{
    common::{
        ciphersuite::CipherSuiteId,
        h2s::{constant::XOF_NO_OF_BYTES, HashToScalarParameter},
    },
    curves::bls12_381::{G1Projective, G2Projective},
    Error,
};
use group::Group;

/// BBS BLS12-381 ciphersuites.
pub mod bls12_381;
/// BBS BLS12-381-Sha-256 ciphersuites.
pub mod bls12_381_sha_256;
/// BBS BLS12-381-Shake-256 ciphersuites.
pub mod bls12_381_shake_256;

pub(crate) trait BbsCiphersuiteParameters:
    HashToScalarParameter
{
    /// A seed value with global scope for `generator_seed` as defined in
    /// BBS signature Spec which is used by the `create_generators ` operation
    /// to compute the required set of message generators.
    fn generator_seed() -> Vec<u8> {
        [Self::ID.as_octets(), b"MESSAGE_GENERATOR_SEED"].concat()
    }

    /// Generator DST which is used by the `create_generators ` operation.
    fn generator_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"SIG_GENERATOR_DST_"].concat()
    }

    /// Seed DST which is used by the `create_generators ` operation.
    fn generator_seed_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"SIG_GENERATOR_SEED_"].concat()
    }

    /// Point on G1 to be used in signature and proof computation and
    /// verification.
    fn p1() -> G1Projective {
        G1Projective::generator()
    }

    /// Point on G2 to be used during signature and proof verification.
    fn p2() -> G2Projective {
        G2Projective::generator()
    }

    /// Create generators as specified in BBS specification.
    fn create_generators(
        count: usize,
        n: &mut u64,
        v: &mut [u8; XOF_NO_OF_BYTES],
        with_fresh_state: bool,
    ) -> Result<Vec<G1Projective>, Error>;
}
