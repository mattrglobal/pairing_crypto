use super::{
    dtos::{BbsSignRequest, BbsVerifyRequest},
    utils::digest_messages,
};
use crate::{
    bbs::core::{
        constants::BBS_BLS12381G1_SIGNATURE_LENGTH,
        generator::Generators,
        key_pair::{PublicKey, SecretKey},
        signature::Signature,
        types::Message,
    },
    curves::bls12_381::hash_to_curve::ExpandMessage,
    error::Error,
};

// Create a BLS12-381 signature.
pub(crate) fn sign<T, X>(
    request: &BbsSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error>
where
    T: AsRef<[u8]>,
    X: ExpandMessage,
{
    // Parse the secret key
    let sk = SecretKey::from_bytes(request.secret_key)?;

    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages::<_, X>(request.messages)?;

    // Derive generators
    let generators = Generators::new::<X>(messages.len())?;

    // Produce the signature and return
    Signature::new::<_, _, X>(
        &sk,
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
    )
    .map(|sig| sig.to_octets())
}

// Verify a BLS12-381 signature.
pub(crate) fn verify<T, X>(
    request: &BbsVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    X: ExpandMessage,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages::<_, X>(request.messages)?;

    // Derive generators
    let generators = Generators::new::<X>(messages.len())?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    signature.verify::<_, _, X>(
        &pk,
        request.header.as_ref(),
        &generators,
        &messages,
    )
}
