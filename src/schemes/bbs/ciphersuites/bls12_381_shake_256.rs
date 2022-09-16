use super::{
    bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
    BbsCiphersuiteParameters,
    CipherSuiteId,
};
use crate::{
    bbs::{
        core::{
            constants::XOF_NO_OF_BYTES,
            hash_utils::{do_create_generators, do_hash_to_scalar},
        },
        BbsProofGenRequest,
        BbsProofVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
    curves::bls12_381::{hash_to_curve::ExpandMsgXof, G1Projective, Scalar},
    Error,
};
use sha3::Shake256;

#[derive(Debug, Clone)]
pub(crate) struct Bls12381Shake256CipherSuiteParameter;

impl<'a> BbsCiphersuiteParameters<'a> for Bls12381Shake256CipherSuiteParameter {
    const ID: CipherSuiteId = CipherSuiteId::BbsBls12381G1XofShake256;

    fn hash_to_scalar(
        message: &[u8],
        count: usize,
        dst: Option<&[u8]>,
    ) -> Result<Vec<Scalar>, Error> {
        do_hash_to_scalar::<Self, ExpandMsgXof<Shake256>>(message, count, dst)
    }

    fn create_generators(
        count: usize,
        n: &mut u64,
        v: &mut [u8; XOF_NO_OF_BYTES],
        with_fresh_state: bool,
    ) -> Result<Vec<G1Projective>, Error> {
        do_create_generators::<Self, ExpandMsgXof<Shake256>>(
            count,
            n,
            v,
            with_fresh_state,
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

/// Create generators.
#[cfg(feature = "__private_generator_api")]
pub fn create_generators(count: usize) -> Result<Vec<Vec<u8>>, Error> {
    crate::bbs::api::generators::create_generators::<
        Bls12381Shake256CipherSuiteParameter,
    >(count)
}
