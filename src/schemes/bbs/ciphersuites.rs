use crate::{
    common::{
        ciphersuite::CipherSuiteId,
        hash_param::{
            constant::XOF_NO_OF_BYTES,
            h2c::HashToCurveParameter,
            h2s::HashToScalarParameter,
        },
        serialization::i2osp,
    },
    curves::bls12_381::{
        hash_to_curve::{ExpandMessageState, InitExpandMessage},
        G1Projective,
        G2Projective,
    },
    Error,
};
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
    ) -> Result<Vec<G1Projective>, Error> {
        let generator_seed_dst = Self::generator_seed_dst();

        if with_fresh_state {
            *n = 1;

            //  v = expand_message(generator_seed, seed_dst, seed_len)
            let mut expander = Self::Expander::init_expand(
                &Self::generator_seed(),
                &generator_seed_dst,
                XOF_NO_OF_BYTES,
            );
            expander.read_into(v);
        }

        let mut points = Vec::with_capacity(count);

        let mut i = 0;
        while i < count {
            // v = expand_message(v || I2OSP(n, 4), seed_dst, seed_len)
            let mut expander = Self::Expander::init_expand(
                &[v.as_ref(), &i2osp(*n, 4)?].concat(),
                &generator_seed_dst,
                XOF_NO_OF_BYTES,
            );
            expander.read_into(v);

            *n += 1;

            // candidate = hash_to_curve_g1(v, generator_dst)
            let candidate = Self::hash_to_g1(v, &Self::generator_dst())?;

            if (candidate.is_identity().unwrap_u8() == 1)
                || candidate == Self::p1()
                || points.iter().any(|e| e == &candidate)
            {
                continue;
            }

            points.push(candidate);
            i += 1;
        }
        Ok(points)
    }
}
