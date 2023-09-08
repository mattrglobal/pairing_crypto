use crate::{
    bbs::generator::GeneratorsParameters,
    common::{
        ciphersuite::CipherSuiteId,
        hash_param::{
            constant::{DEFAULT_DST_SUFFIX_H2S, XOF_NO_OF_BYTES},
            h2c::HashToCurveParameter,
            h2s::HashToScalarParameter,
        },
        interface::InterfaceId,
    },
    curves::bls12_381::{
        hash_to_curve::{ExpandMessageState, InitExpandMessage},
        G1Projective,
        G2Projective,
    },
    Error,
};
use blstrs::Scalar;
use group::Group;

/// BBS BLS12-381 ciphersuites.
pub mod bls12_381;
/// BBS BLS12-381-Sha-256 ciphersuites.
pub mod bls12_381_g1_sha_256;
/// BBS BLS12-381-Shake-256 ciphersuites.
pub mod bls12_381_g1_shake_256;

pub(crate) trait BbsCiphersuiteParameters:
    HashToScalarParameter + HashToCurveParameter
{
    /// A seed value with global scope for `generator_seed` as defined in
    /// BBS signature Spec which is used by the `create_generators ` operation
    /// to compute the required set of message generators.
    fn bp_generator_seed() -> Vec<u8> {
        [Self::ID.as_octets(), b"H2G_HM2S_BP_MESSAGE_GENERATOR_SEED"].concat()
    }

    // The G1 base point generator seed.

    /// Seed DST which is used by the `create_generators ` operation.
    fn bp_generator_seed_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"H2G_HM2S_SIG_GENERATOR_SEED_"].concat()
    }

    /// Generator DST which is used by the `create_generators ` operation.
    fn bp_generator_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"H2G_HM2S_SIG_GENERATOR_DST_"].concat()
    }

    /// Point on G1 to be used in signature and proof computation and
    /// verification.
    fn p1() -> Result<G1Projective, Error> {
        let mut n = 1;
        let mut v = [0u8; XOF_NO_OF_BYTES];

        let base_generator = GeneratorsParameters {
            generator_seed: Self::bp_generator_seed(),
            generator_dst: Self::bp_generator_dst(),
            seed_dst: Self::bp_generator_seed_dst(),
            hash_to_curve: Self::hash_to_curve,
            expand_message: Self::expand_message,
        };

        Ok(base_generator.create_generators(1, &mut n, &mut v, true)?[0])
    }

    /// Hash a message and a dst to an output that is XOF_NO_OF_BYTES long.
    fn expand_message(
        message: &[u8],
        dst: &[u8],
        dest: &mut [u8; XOF_NO_OF_BYTES],
    ) {
        let mut expander =
            Self::Expander::init_expand(message, dst, XOF_NO_OF_BYTES);
        expander.read_into(dest);
    }

    /// Hash a message and a dst to a point of g1.
    fn hash_to_curve(
        message: &[u8],
        dst: &[u8],
    ) -> Result<G1Projective, Error> {
        <Self as HashToCurveParameter>::hash_to_g1(message, dst)
    }

    /// Point on G2 to be used during signature and proof verification.
    fn p2() -> G2Projective {
        G2Projective::generator()
    }

    fn hash_to_e(data_to_hash: &[u8], api_id: &[u8]) -> Result<Scalar, Error> {
        let e_dst = [api_id, DEFAULT_DST_SUFFIX_H2S.as_bytes()].concat();
        Self::hash_to_scalar(data_to_hash, Some(&e_dst))
    }
}
