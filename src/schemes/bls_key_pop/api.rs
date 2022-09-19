use crate::{
    bls::core::key_pair::{
        PublicKey as BlsPublicKey,
        SecretKey as BlsSecretKey,
    },
    Error,
};

///  Generate a commitment to their BLS secret key.
pub fn key_pop<T>(
    bls_sk: &BlsSecretKey,
    aud: T,
    dst: Option<T>,
    extra_info: Option<T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    todo!()
}

///  Validate a proof of possession of a BLS secret key (KeyPoP) created using
/// the `key_pop` operation.
pub fn key_pop_verify<T>(
    bls_pk: &BlsPublicKey,
    aud: T,
    dst: Option<T>,
    extra_info: Option<T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    todo!()
}
