use super::{
    bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
    BbsCiphersuiteParameters,
    CipherSuiteId,
};
use crate::{
    bbs::{
        core::utils::do_create_generators,
        BbsProofGenRequest,
        BbsProofVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
    common::h2s::{
        constant::XOF_NO_OF_BYTES,
        do_hash_to_scalar,
        HashToScalarParameter,
    },
    curves::bls12_381::{hash_to_curve::ExpandMsgXmd, G1Projective, Scalar},
    Error,
};
use sha2::Sha256;

#[derive(Debug, Clone)]
pub(crate) struct Bls12381Sha256CipherSuiteParameter;

impl HashToScalarParameter for Bls12381Sha256CipherSuiteParameter {
    const ID: CipherSuiteId = CipherSuiteId::BbsBls12381G1XmdSha256;

    fn hash_to_scalar(
        message: &[u8],
        count: usize,
        dst: Option<&[u8]>,
    ) -> Result<Vec<Scalar>, Error> {
        do_hash_to_scalar::<Self, ExpandMsgXmd<Sha256>>(message, count, dst)
    }
}

impl BbsCiphersuiteParameters for Bls12381Sha256CipherSuiteParameter {
    fn create_generators(
        count: usize,
        n: &mut u64,
        v: &mut [u8; XOF_NO_OF_BYTES],
        with_fresh_state: bool,
    ) -> Result<Vec<G1Projective>, Error> {
        do_create_generators::<Self, ExpandMsgXmd<Sha256>>(
            count,
            n,
            v,
            with_fresh_state,
        )
    }
}

/// Create a BLS12-381-Sha-256 BBS signature.
/// Security Warning: `secret_key` and `public_key` in `request` must be related
/// key-pair generated using `KeyPair` APIs.
pub fn sign<T>(
    request: &BbsSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::signature::sign::<_, Bls12381Sha256CipherSuiteParameter>(
        request,
    )
}

/// Verify a BLS12-381-Sha-256 BBS signature.
pub fn verify<T>(request: &BbsVerifyRequest<'_, T>) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::signature::verify::<_, Bls12381Sha256CipherSuiteParameter>(
        request,
    )
}

/// Generate a BLS12-381-Sha-256 signature proof of knowledge.
pub fn proof_gen<T>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::proof::proof_gen::<_, Bls12381Sha256CipherSuiteParameter>(
        request,
    )
}

/// Verify a BLS12-381-Sha-256 signature proof of knowledge.
pub fn proof_verify<T>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::proof::proof_verify::<_, Bls12381Sha256CipherSuiteParameter>(
        request,
    )
}
