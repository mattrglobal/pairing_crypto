use super::{
    dtos::{BbsProofGenRequest, BbsProofVerifyRequest},
    utils::{
        digest_messages,
        digest_proof_messages,
        digest_revealed_proof_messages,
    },
};
use crate::{
    error::Error,
    schemes::bbs::ciphersuites::bls12_381::{
        Generators,
        Message,
        Proof,
        ProofMessage,
        PublicKey,
        Signature,
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
    },
};

/// Generate a signature proof of knowledge.
pub fn proof_gen(request: BbsProofGenRequest) -> Result<Vec<u8>, Error> {
    // Parse public key from request
    let pk = PublicKey::from_vec(request.public_key)?;

    let mut digested_messages = vec![];
    if request.messages.is_some() {
        let request_messages = request.messages.as_ref().unwrap();
        let request_messages = request_messages
            .iter()
            .map(|element| element.value.clone())
            .collect::<Vec<Vec<u8>>>();
        // Digest the supplied messages
        digested_messages = digest_messages(Some(&request_messages))?;
    }

    // Derive generators
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        digested_messages.len(),
    )?;
    // Parse signature from request
    let signature = Signature::from_vec(request.signature)?;

    // Verify the signature to check the messages supplied are valid
    signature.verify(
        &pk,
        request.header.as_ref(),
        &generators,
        &digested_messages,
    )?;

    // Digest the supplied messages
    let messages: Vec<ProofMessage> =
        match digest_proof_messages(request.messages.as_ref()) {
            Ok(messages) => messages,
            Err(e) => return Err(e),
        };

    let proof = Proof::new(
        &pk,
        &signature,
        request.header.as_ref(),
        request.presentation_message.as_ref(),
        &generators,
        &messages,
    )?;

    Ok(proof.to_octets())
}

/// Verify a signature proof of knowledge.
pub fn proof_verify(request: BbsProofVerifyRequest) -> Result<bool, Error> {
    // Parse public key from request
    let public_key = PublicKey::from_vec(request.public_key)?;

    // Digest the revealed proof messages
    let messages: Vec<(usize, Message)> = digest_revealed_proof_messages(
        request.messages.as_ref(),
        request.total_message_count,
    )?;

    // Derive generators
    let generators = Generators::new(
        GLOBAL_BLIND_VALUE_GENERATOR_SEED,
        GLOBAL_SIG_DOMAIN_GENERATOR_SEED,
        GLOBAL_MESSAGE_GENERATOR_SEED,
        request.total_message_count,
    )?;

    let proof = Proof::from_octets(request.proof)?;

    proof.verify(
        &public_key,
        request.header.as_ref(),
        request.presentation_message.as_ref(),
        &generators,
        &messages,
    )
}
