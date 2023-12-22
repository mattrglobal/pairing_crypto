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

    // The G1 base point generator seed.
    fn bp_generator_seed() -> Vec<u8> {
        [Self::ID.as_octets(), b"BP_MESSAGE_GENERATOR_SEED"].concat()
    }

    /// Seed DST which is used by the `create_generators ` operation.
    fn generator_seed_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"SIG_GENERATOR_SEED_"].concat()
    }

    /// Generator DST which is used by the `create_generators ` operation.
    fn generator_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"SIG_GENERATOR_DST_"].concat()
    }

    /// Point on G1 to be used in signature and proof computation and
    /// verification.
    fn p1() -> Result<G1Projective, Error> {
        let mut n = 1;
        let mut v = [0u8; XOF_NO_OF_BYTES];
        Ok(Self::create_generators(
            &Self::bp_generator_seed(),
            1,
            &mut n,
            &mut v,
            true,
        )?[0])
    }

    /// Point on G2 to be used during signature and proof verification.
    fn bp2() -> G2Projective {
        G2Projective::generator()
    }

    /// Create generators as specified in BBS specification.
    fn create_generators(
        generator_seed: &[u8],
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
                generator_seed,
                &generator_seed_dst,
                XOF_NO_OF_BYTES,
            );
            expander.read_into(v);
        }

        let mut points = Vec::with_capacity(count);

        while *n <= count.try_into().unwrap() {
            // v = expand_message(v || I2OSP(n, 8), seed_dst, seed_len)
            let mut expander = Self::Expander::init_expand(
                &[v.as_ref(), &i2osp(*n, 8)?].concat(),
                &generator_seed_dst,
                XOF_NO_OF_BYTES,
            );
            expander.read_into(v);

            *n += 1;

            // generator_i = hash_to_curve_g1(v, generator_dst)
            let generator_i = Self::hash_to_g1(v, &Self::generator_dst())?;
            points.push(generator_i);
        }
        Ok(points)
    }
}
