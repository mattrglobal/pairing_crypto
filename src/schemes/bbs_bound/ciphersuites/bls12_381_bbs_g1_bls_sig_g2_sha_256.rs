use crate::{
    bbs::ciphersuites::{
        bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
        bls12_381_g1_sha_256::Bls12381Sha256CipherSuiteParameter,
        bls12_381_g1_shake_256::Bls12381Shake256CipherSuiteParameter,
    },
    bbs_bound::{
        api::dtos::{
            BbsBoundSignRequest,
            BbsBoundVerifyRequest,
            BlsKeyPopGenRequest,
            BlsKeyPopVerifyRequest,
        },
        BbsBoundProofGenRequest,
        BbsBoundProofVerifyRequest,
    },
    bls::ciphersuites::{
        bls12_381::BLS_SIG_BLS12381G2_SIGNATURE_LENGTH,
        bls12_381_g2_sha_256_aug::Bls12381G2XmdSha256AugCipherSuiteParameter,
    },
    Error,
};

pub use crate::schemes::bbs::core::{
    constants::MIN_KEY_GEN_IKM_LENGTH,
    key_pair::{
        KeyPair as BbsKeyPair,
        PublicKey as BbsPublicKEy,
        SecretKey as BbsSecretKey,
    },
};

///  Generate a commitment to their BLS secret key.
pub fn bls_key_pop(
    request: &BlsKeyPopGenRequest<'_>,
) -> Result<[u8; BLS_SIG_BLS12381G2_SIGNATURE_LENGTH], Error> {
    crate::bbs_bound::api::bls_key_pop::generate::<
        Bls12381Shake256CipherSuiteParameter,
        Bls12381G2XmdSha256AugCipherSuiteParameter,
    >(request)
}

///  Validate a proof of possession of a BLS secret key (KeyPoP) created using
/// the `key_pop` operation.
pub fn bls_key_pop_verify(
    request: &BlsKeyPopVerifyRequest<'_>,
) -> Result<bool, Error> {
    crate::bbs_bound::api::bls_key_pop::verify::<
        Bls12381Shake256CipherSuiteParameter,
        Bls12381G2XmdSha256AugCipherSuiteParameter,
    >(request)
}

/// Create a BLS12-381-G1-Shake-256 BBS bound signature.
/// Security Warning: `secret_key` and `public_key` in `request` must be related
/// key-pair generated using `KeyPair` APIs.
pub fn sign<T>(
    request: &BbsBoundSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs_bound::api::signature::sign::<
        _,
        Bls12381Sha256CipherSuiteParameter,
    >(request)
}

/// Verify a BLS12-381-G1-Sha-256 BBS bound signature.
pub fn verify<T>(request: &BbsBoundVerifyRequest<'_, T>) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs_bound::api::signature::verify::<
        _,
        Bls12381Sha256CipherSuiteParameter,
    >(request)
}

pub use crate::schemes::bbs_bound::api::proof::get_proof_size;

/// Generate a BLS12-381-G1-Shake-256 BBS bound signature proof of knowledge.
pub fn proof_gen<T>(
    request: &BbsBoundProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs_bound::api::proof::proof_gen::<
        _,
        Bls12381Sha256CipherSuiteParameter,
    >(request)
}

/// Verify a BLS12-381-G1-Sha-256 BBS bound signature proof of knowledge.
pub fn proof_verify<T>(
    request: &BbsBoundProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    crate::bbs_bound::api::proof::proof_verify::<
        _,
        Bls12381Sha256CipherSuiteParameter,
    >(request)
}
