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
    },
};

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

#[cfg(not(feature = "alloc"))]
use std::collections::BTreeMap;

/// Return the size of proof in bytes for `num_undisclosed_messages`.
pub fn get_proof_size(num_undisclosed_messages: usize) -> usize {
    Proof::get_size(num_undisclosed_messages)
}

/// Generate a signature proof of knowledge.
pub fn proof_gen<T: AsRef<[u8]>>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error> {
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    let mut digested_messages = vec![];
    if let Some(request_messages) = request.messages {
        let request_messages = request_messages
            .iter()
            .map(|element| element.value.as_ref())
            .collect::<Vec<_>>();
        // Digest the supplied messages
        digested_messages = digest_messages(Some(&request_messages))?;
    }

    // Derive generators
    let generators = Generators::new(digested_messages.len())?;
    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    // Verify the signature to check the messages supplied are valid
    if !(signature.verify(
        &pk,
        request.header.as_ref(),
        &generators,
        &digested_messages,
    )?) {
        return Err(Error::SignatureVerification);
    }

    // Digest the supplied messages
    let messages: Vec<ProofMessage> =
        match digest_proof_messages(request.messages) {
            Ok(messages) => messages,
            Err(e) => return Err(e),
        };

    // Generate the proof
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
pub fn proof_verify<T: AsRef<[u8]>>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error> {
    // Parse public key from request
    let public_key = PublicKey::from_octets(request.public_key)?;

    // Digest the revealed proof messages
    let messages: BTreeMap<usize, Message> = digest_revealed_proof_messages(
        request.messages,
        request.total_message_count,
    )?;

    // Derive generators
    let generators = Generators::new(request.total_message_count)?;

    let proof = Proof::from_octets(request.proof)?;

    proof.verify(
        &public_key,
        request.header.as_ref(),
        request.presentation_message.as_ref(),
        &generators,
        &messages,
    )
}
