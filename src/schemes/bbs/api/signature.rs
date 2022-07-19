use super::{
    dtos::{BbsSignRequest, BbsVerifyRequest},
    utils::digest_messages,
};
use crate::{
    bbs::core::constants::BBS_BLS12381G1_SIGNATURE_LENGTH,
    error::Error,
    schemes::bbs::ciphersuites::bls12_381::{
        Generators,
        Message,
        PublicKey,
        SecretKey,
        Signature,
    },
};

/// Creates a signature.
/// Security Warning: `secret_key` and `public_key` in `request` must be related
/// key-pair generated using `KeyPair` APIs.
pub fn sign<T: AsRef<[u8]>>(
    request: &BbsSignRequest<'_, T>,
) -> Result<[u8; BBS_BLS12381G1_SIGNATURE_LENGTH], Error> {
    // Parse the secret key
    let sk = SecretKey::from_bytes(request.secret_key)?;

    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages(request.messages)?;

    // Derive generators
    let generators = Generators::new(messages.len())?;

    // Produce the signature and return
    Signature::new(&sk, &pk, request.header.as_ref(), &generators, &messages)
        .map(|sig| sig.to_octets())
}

/// Verifies a signature.
pub fn verify<T: AsRef<[u8]>>(
    request: &BbsVerifyRequest<'_, T>,
) -> Result<bool, Error> {
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages(request.messages)?;

    // Derive generators
    let generators = Generators::new(messages.len())?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    signature.verify(&pk, request.header.as_ref(), &generators, &messages)
}
