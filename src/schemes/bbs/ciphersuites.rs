use crate::{
    curves::bls12_381::{G1Projective, Scalar},
    Error,
};

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
                b"BBS_BLS12381G1_XOF:SHA-256_SSWU_RO_"
            }
            CipherSuiteId::BbsBls12381G1XofShake256 => {
                b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_"
            }
        }
    }
}

pub(crate) trait BbsCipherSuiteParameter<'a> {
    /// Ciphersuite ID.
    const ID: CipherSuiteId;

    /// Default domain separation tag for `hash_to_scalar` operation.
    const DEFAULT_HASH_TO_SCALAR_DST: &'static [u8];

    /// Default domain separation tag to be used in [MapMessageToScalarAsHash](https://identity.foundation/bbs-signature/draft-bbs-signatures.html#name-mapmessagetoscalarashash).
    const DEFAULT_MAP_MESSAGE_TO_SCALAR_DST: &'static [u8];

    /// A seed value with global scope for `generator_seed` as defined in
    /// BBS signature Spec which is used by the `create_generators ` operation
    /// to compute the required set of message generators.
    const GENERATOR_SEED: &'static [u8];

    /// Generator DST which is used by the `create_generators ` operation.
    const GENERATOR_DST: &'static [u8];

    /// Seed DST which is used by the `create_generators ` operation.
    const GENERATOR_SEED_DST: &'static [u8];

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
        generator_seed: Option<&[u8]>,
        generator_seed_dst: Option<&[u8]>,
        generator_dst: Option<&[u8]>,
    ) -> Result<Vec<G1Projective>, Error>;
}
