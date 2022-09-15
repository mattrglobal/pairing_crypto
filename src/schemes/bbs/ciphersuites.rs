use super::core::constants::XOF_NO_OF_BYTES;
use crate::{
    curves::bls12_381::{G1Projective, G2Projective, Scalar},
    Error,
};
use core::fmt::Debug;
use group::Group;

/// BBS BLS12-381 ciphersuites.
pub mod bls12_381;
/// BBS BLS12-381-Sha-256 ciphersuites.
pub mod bls12_381_sha_256;
/// BBS BLS12-381-Shake-256 ciphersuites.
pub mod bls12_381_shake_256;

/// BBS Ciphersuite ID.
pub(crate) enum CipherSuiteId {
    BbsBls12381G1XmdSha256,
    BbsBls12381G1XofShake256,
}

impl CipherSuiteId {
    /// Convert to a String represenation.
    pub(crate) fn as_octets(&self) -> &[u8] {
        match &self {
            CipherSuiteId::BbsBls12381G1XmdSha256 => {
                b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
            }
            CipherSuiteId::BbsBls12381G1XofShake256 => {
                b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_"
            }
        }
    }
}

pub(crate) trait BbsCiphersuiteParameters<'a>: Debug + Clone {
    /// Ciphersuite ID.
    const ID: CipherSuiteId;

    /// Default domain separation tag for `hash_to_scalar` operation.
    fn default_hash_to_scalar_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"H2S_"].concat()
    }

    /// Default domain separation tag to be used in [MapMessageToScalarAsHash](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-mapmessagetoscalarashash).
    fn default_map_message_to_scalar_as_hash_dst() -> Vec<u8> {
        [Self::ID.as_octets(), b"MAP_MESSAGE_TO_SCALAR_AS_HASH_"].concat()
    }

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

    /// Hash arbitrary data to `n` number of scalars as specified in BBS
    /// specification.
    fn hash_to_scalar(
        msg_octets: &[u8],
        count: usize,
        dst: Option<&[u8]>,
    ) -> Result<Vec<Scalar>, Error>;

    /// Create generators as specified in BBS specification.
    fn create_generators(
        count: usize,
        n: &mut u64,
        v: &mut [u8; XOF_NO_OF_BYTES],
        with_fresh_state: bool,
    ) -> Result<Vec<G1Projective>, Error>;
}
