use super::{
    bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
    BbsCiphersuiteParameters,
    CipherSuiteId,
};
use crate::{
    bbs::{
        BbsProofGenRequest,
        BbsProofVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
    common::{
        ciphersuite::CipherSuiteParameter,
        hash_param::{
            h2c::HashToCurveParameter,
            h2s::HashToScalarParameter,
            ExpandMessageParameter,
        },
    },
    curves::bls12_381::hash_to_curve::ExpandMsgXmd,
    Error,
};
use sha2::Sha256;

#[derive(Debug, Clone)]
pub(crate) struct Bls12381Sha256CipherSuiteParameter;

impl CipherSuiteParameter for Bls12381Sha256CipherSuiteParameter {
    const ID: CipherSuiteId = CipherSuiteId::BbsBls12381G1XmdSha256;
}

impl ExpandMessageParameter for Bls12381Sha256CipherSuiteParameter {
    type Expander = ExpandMsgXmd<Sha256>;
}

impl HashToScalarParameter for Bls12381Sha256CipherSuiteParameter {}

impl HashToCurveParameter for Bls12381Sha256CipherSuiteParameter {}

impl BbsCiphersuiteParameters for Bls12381Sha256CipherSuiteParameter {}

/// Create a BLS12-381-G1-Sha-256 BBS signature.
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

/// Verify a BLS12-381-G1-Sha-256 BBS signature.
pub fn verify<T>(request: &BbsVerifyRequest<'_, T>) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs::api::signature::verify::<_, Bls12381Sha256CipherSuiteParameter>(
        request,
    )
}

/// Generate a BLS12-381-G1-Sha-256 BBS signature proof of knowledge.
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

/// Verify a BLS12-381-G1-Sha-256 BBS signature proof of knowledge.
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

/// Create generators.
#[cfg(feature = "__private_generator_api")]
pub fn create_generators(
    count: usize,
    private_holder_binding: Option<bool>,
) -> Result<Vec<Vec<u8>>, Error> {
    crate::bbs::api::generators::create_generators::<
        Bls12381Sha256CipherSuiteParameter,
    >(count, private_holder_binding)
}
