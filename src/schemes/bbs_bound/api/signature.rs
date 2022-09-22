use super::dtos::{BbsBoundSignRequest, BbsBoundVerifyRequest};
use crate::{
    bbs::{
        api::utils::digest_messages,
        ciphersuites::{
            bls12_381::BBS_BLS12381G1_SIGNATURE_LENGTH,
            BbsCiphersuiteParameters,
        },
        core::{
            generator::memory_cached_generator::MemoryCachedGenerators,
            key_pair::{PublicKey, SecretKey},
            signature::Signature,
            types::Message,
        },
    },
    error::Error,
};

use crate::bls::core::key_pair::{
    PublicKey as BlsPublicKey,
    SecretKey as BlsSecretKey,
};

// Create a BBS Bound signature.
pub(crate) fn sign<T, C>(
    request: &BbsBoundSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse the secret key
    let sk = SecretKey::from_bytes(request.secret_key)?;

    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Parse BLS public key from request
    let bls_pk = BlsPublicKey::from_octets(request.bls_public_key)?;
    // Validate the public key; it should not be an identity and should
    // belong to subgroup.
    if bls_pk.is_valid().unwrap_u8() == 0 {
        return Err(Error::InvalidPublicKey);
    }

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages::<_, C>(request.messages)?;

    // Derive generators
    let generators =
        MemoryCachedGenerators::<C>::new(messages.len(), Some(true))?;

    // Produce the signature and return
    Signature::new_bound::<_, _, _, C>(
        &sk,
        &pk,
        &bls_pk,
        request.header.as_ref(),
        &generators,
        &messages,
    )
    .map(|sig| sig.to_octets())
}

// Verify a BBS bound signature.
pub(crate) fn verify<T, C>(
    request: &BbsBoundVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Parse BLS secret key from request
    let bls_sk = BlsSecretKey::from_bytes(request.bls_secret_key)?;

    // Digest the supplied messages
    let mut messages: Vec<Message> = digest_messages::<_, C>(request.messages)?;
    messages.push(Message(*bls_sk.0));

    // Derive generators
    let generators =
        MemoryCachedGenerators::<C>::new(messages.len() - 1, Some(true))?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    signature.verify::<_, _, _, C>(
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
    )
}
