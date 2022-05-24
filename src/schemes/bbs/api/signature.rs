use super::dtos::{BbsSignRequest, BbsVerifyRequest};
use super::utils::{digest_messages, BbsErrorCode};
use crate::bls12_381::bbs::{
    core::Error, core::Message, MessageGenerators, PublicKey, SecretKey,
    Signature,
};

/// Creates a signature
pub fn sign(request: BbsSignRequest) -> Result<[u8; 112], Error> {
    // Parse the secret key
    let sk = match SecretKey::from_vec(request.secret_key) {
        Ok(result) => result,
        Err(_) => {
            return Err(Error::new_bbs_error(
                BbsErrorCode::ParsingError,
                "Failed to parse secret key",
            ))
        }
    };

    // Derive the public key from the secret key
    let pk = PublicKey::from(&sk);

    // Digest the supplied messages
    let messages: Vec<Message> = match digest_messages(request.messages) {
        Ok(messages) => messages,
        Err(e) => return Err(e),
    };

    // Use generators derived from the signers public key
    // TODO this approach is likely to change soon
    let generators = MessageGenerators::from_public_key(pk, messages.len());

    // Produce the signature and return
    match Signature::new(&sk, &generators, &messages) {
        Ok(sig) => Ok(sig.to_bytes()),
        Err(e) => Err(e),
    }
}

/// Verifies a signature
pub fn verify(request: BbsVerifyRequest) -> Result<bool, Error> {
    // Parse public key from request
    let pk = match PublicKey::from_vec(request.public_key) {
        Ok(result) => result,
        Err(_) => {
            return Err(Error::new_bbs_error(
                BbsErrorCode::ParsingError,
                "Failed to parse public key",
            ))
        }
    };

    // Digest the supplied messages
    let messages: Vec<Message> = match digest_messages(request.messages) {
        Ok(messages) => messages,
        Err(e) => return Err(e),
    };

    // Use generators derived from the signers public key
    // TODO this approach is likely to change soon
    let generators = MessageGenerators::from_public_key(pk, messages.len());

    // Parse signature from request
    let signature = match Signature::from_vec(request.signature) {
        Ok(result) => result,
        Err(e) => {
            return Err(Error::new_bbs_error(BbsErrorCode::ParsingError, &e))
        }
    };

    Ok(signature.verify(&pk, &generators, &messages))
}
