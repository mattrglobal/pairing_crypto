use super::{
    bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
    BbsCipherSuiteParameter,
    CipherSuiteId,
};
use crate::{
    bbs::{
        core::hash_utils::{do_create_generators, do_hash_to_scalar},
        BbsProofGenRequest,
        BbsProofVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
    curves::bls12_381::{hash_to_curve::ExpandMsgXof, G1Projective, Scalar},
    Error,
};
use sha3::Shake256;

pub(crate) struct Bls12381Shake256CipherSuiteParameter;

impl<'a> BbsCipherSuiteParameter<'a> for Bls12381Shake256CipherSuiteParameter {
    const ID: CipherSuiteId = CipherSuiteId::BbsBls12381G1XofShake256;

    const DEFAULT_HASH_TO_SCALAR_DST: &'static [u8] =
        b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2S_";

    const DEFAULT_MAP_MESSAGE_TO_SCALAR_AS_HASH_DST: &'static [u8] =
        b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_MAP_MESSAGE_TO_SCALAR_AS_HASH_";

    const GENERATOR_SEED: &'static [u8] =
        b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_MESSAGE_GENERATOR_SEED";

    const GENERATOR_DST: &'static [u8] =
        b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_GENERATOR_DST_";

    const GENERATOR_SEED_DST: &'static [u8] =
        b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_GENERATOR_SEED_";

    fn hash_to_scalar(
        message: &[u8],
        count: usize,
        dst: Option<&[u8]>,
    ) -> Result<Vec<Scalar>, Error> {
        do_hash_to_scalar::<Self, ExpandMsgXof<Shake256>>(message, count, dst)
    }

    fn create_generators(
        count: usize,
        generator_seed: Option<&[u8]>,
        generator_seed_dst: Option<&[u8]>,
        generator_dst: Option<&[u8]>,
    ) -> Result<Vec<G1Projective>, Error> {
        do_create_generators::<Self, ExpandMsgXof<Shake256>>(
            count,
            generator_seed,
            generator_seed_dst,
            generator_dst,
        )
    }
}

/// Create a BLS12-381-Shake-256 BBS signature.
/// Security Warning: `secret_key` and `public_key` in `request` must be related
/// key-pair generated using `KeyPair` APIs.
pub fn sign<T>(
    request: &BbsSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::signature::sign::<_, Bls12381Shake256CipherSuiteParameter>(
        request,
    )
}

/// Verify a BLS12-381-Shake-256 BBS signature.
pub fn verify<T>(request: &BbsVerifyRequest<'_, T>) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::signature::verify::<_, Bls12381Shake256CipherSuiteParameter>(
        request,
    )
}

/// Generate a BLS12-381-Shake-256 signature proof of knowledge.
pub fn proof_gen<T>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::proof::proof_gen::<_, Bls12381Shake256CipherSuiteParameter>(
        request,
    )
}

/// Verify a BLS12-381-Shake-256 signature proof of knowledge.
pub fn proof_verify<T>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::proof::proof_verify::<
        _,
        Bls12381Shake256CipherSuiteParameter,
    >(request)
}
