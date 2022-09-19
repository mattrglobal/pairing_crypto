use crate::{
    bbs::ciphersuites::bls12_381_g1_shake_256::Bls12381Shake256CipherSuiteParameter,
    bls::{
        ciphersuites::{
            bls12_381::BLS_SIG_BLS12381G2_SIGNATURE_LENGTH,
            bls12_381_g2_shake_256_aug::Bls12381G2XofShake256AugCipherSuiteParameter,
        },
        core::key_pair::{
            PublicKey as BlsPublicKey,
            SecretKey as BlsSecretKey,
        },
    },
    Error,
};

///  Generate a commitment to their BLS secret key.
pub fn generate(
    bls_sk: &BlsSecretKey,
    aud: &[u8],
    dst: Option<&[u8]>,
    extra_info: Option<&[u8]>,
) -> Result<[u8; BLS_SIG_BLS12381G2_SIGNATURE_LENGTH], Error> {
    crate::schemes::bls_key_pop::api::generate::<
        Bls12381Shake256CipherSuiteParameter,
        Bls12381G2XofShake256AugCipherSuiteParameter,
    >(bls_sk, aud, dst, extra_info)
}

///  Validate a proof of possession of a BLS secret key (KeyPoP) created using
/// the `key_pop` operation.
pub fn verify(
    key_pop: &[u8; BLS_SIG_BLS12381G2_SIGNATURE_LENGTH],
    bls_pk: &BlsPublicKey,
    aud: &[u8],
    dst: Option<&[u8]>,
    extra_info: Option<&[u8]>,
) -> Result<bool, Error> {
    crate::schemes::bls_key_pop::api::verify::<
        Bls12381Shake256CipherSuiteParameter,
        Bls12381G2XofShake256AugCipherSuiteParameter,
    >(key_pop, bls_pk, aud, dst, extra_info)
}
