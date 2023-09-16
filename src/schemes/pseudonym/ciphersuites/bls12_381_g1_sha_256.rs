use crate::{
    bbs::{
        ciphersuites::{
            bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
            bls12_381_g1_sha_256::Bls12381Sha256CipherSuiteParameter,
        },
        interface::BbsInterfaceParameter,
    },
    common::interface::{InterfaceId, InterfaceParameter},
    curves::bls12_381::OCTET_POINT_G1_LENGTH,
    error::Error,
    pseudonym::api::dtos::{
        BbsProofGenRequest,
        BbsProofVerifyRequest,
        BbsPseudonymGenRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
};

// BBS Interface for use with pseudonyms
#[derive(Debug, Clone)]
pub(crate) struct Bls12381Sha256InterfaceParameter;

impl InterfaceParameter for Bls12381Sha256InterfaceParameter {
    const ID: InterfaceId = InterfaceId::BbsH2gHm2sNym;
}

impl BbsInterfaceParameter for Bls12381Sha256InterfaceParameter {
    type Ciphersuite = Bls12381Sha256CipherSuiteParameter;
}

/// Create a BLS12-381-G1-Sha-256 BBS signature including a unique
/// Prover identifier.
pub fn sign<T>(
    request: &BbsSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]> + Default,
{
    crate::pseudonym::api::signature::sign::<_, Bls12381Sha256InterfaceParameter>(
        request,
    )
}

/// Verify a BLS12-381-G1-Sha-256 BBS signature including a unique
/// Prover identifier.
pub fn verify<T>(request: &BbsVerifyRequest<'_, T>) -> Result<bool, Error>
where
    T: AsRef<[u8]> + Default,
{
    crate::pseudonym::api::signature::verify::<
        _,
        Bls12381Sha256InterfaceParameter,
    >(request)
}

/// Generate a BLS12-381-G1-Sha-256 BBS signature proof of knowledge including
/// a pseudonym (point of G1 used by the Proof Verifier to link multiple
/// proof presentations by the same Prover).
pub fn proof_gen<T>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]> + Default,
{
    crate::pseudonym::api::proof::proof_gen::<_, Bls12381Sha256InterfaceParameter>(
        request,
    )
}

/// Verify a BLS12-381-G1-Sha-256 BBS signature proof of knowledge including
/// a pseudonym.
pub fn proof_verify<T>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]> + Default,
{
    crate::pseudonym::api::proof::proof_verify::<
        _,
        Bls12381Sha256InterfaceParameter,
    >(request)
}

/// Generate a BLS12-381-G1-Sha-256 BBS pseudonym.
pub fn pseudonym_gen<T>(
    request: &BbsPseudonymGenRequest<T>,
) -> Result<[u8; OCTET_POINT_G1_LENGTH], Error>
where
    T: AsRef<[u8]>,
{
    crate::pseudonym::api::pseudonym::generate::<
        _,
        Bls12381Sha256InterfaceParameter,
    >(request)
}
