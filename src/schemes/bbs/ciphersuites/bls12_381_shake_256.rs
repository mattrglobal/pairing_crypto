use super::bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH;
use crate::{
    bbs::{
        BbsProofGenRequest,
        BbsProofVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
    curves::bls12_381::hash_to_curve::ExpandMsgXof,
    Error,
};
use sha3::Shake256;

/// Create a BLS12-381-Shake-256 BBS signature.
/// Security Warning: `secret_key` and `public_key` in `request` must be related
/// key-pair generated using `KeyPair` APIs.
pub fn sign<T>(
    request: &BbsSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::signature::sign::<_, ExpandMsgXof<Shake256>>(request)
}

/// Verify a BLS12-381-Shake-256 BBS signature.
pub fn verify<T>(request: &BbsVerifyRequest<'_, T>) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::signature::verify::<_, ExpandMsgXof<Shake256>>(request)
}

/// Generate a BLS12-381-Shake-256 signature proof of knowledge.
pub fn proof_gen<T>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::proof::proof_gen::<_, ExpandMsgXof<Shake256>>(request)
}

/// Verify a BLS12-381-Shake-256 signature proof of knowledge.
pub fn proof_verify<T>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::proof::proof_verify::<_, ExpandMsgXof<Shake256>>(request)
}
