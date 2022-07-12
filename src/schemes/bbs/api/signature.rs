use super::{
    dtos::{BbsSignRequest, BbsVerifyRequest},
    utils::digest_messages,
};
use crate::{
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
pub fn sign(request: BbsSignRequest<'_>) -> Result<[u8; 112], Error> {
    // Parse the secret key
    let sk = SecretKey::from_bytes(request.secret_key)?;

    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages(request.messages.as_ref())?;

    // Derive generators
    let generators = Generators::new(messages.len())?;

    // Produce the signature and return
    Signature::new(&sk, &pk, request.header.as_ref(), &generators, &messages)
        .map(|sig| sig.to_octets())
}

/// Verifies a signature.
pub fn verify(request: BbsVerifyRequest<'_>) -> Result<bool, Error> {
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Digest the supplied messages
    let messages: Vec<Message> = digest_messages(request.messages.as_ref())?;

    // Derive generators
    let generators = Generators::new(messages.len())?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    signature.verify(&pk, request.header.as_ref(), &generators, &messages)
}
