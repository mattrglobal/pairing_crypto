use super::{
    dtos::{BbsProofGenRequest, BbsProofVerifyRequest},
    utils::{digest_proof_messages, digest_revealed_proof_messages},
};
use crate::{
    curves::bls12_381::hash_to_curve::ExpandMessage,
    error::Error,
    schemes::bbs::core::{
        generator::Generators,
        key_pair::PublicKey,
        proof::Proof,
        signature::Signature,
        types::Message,
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

// Generate a signature proof of knowledge.
pub(crate) fn proof_gen<T, X>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
    X: ExpandMessage,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    let (digested_messages, proof_messages) =
        digest_proof_messages::<_, X>(request.messages)?;

    // Derive generators
    let generators = Generators::new::<X>(digested_messages.len())?;
    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    let verify_signature = request.verify_signature.unwrap_or(true);
    if verify_signature {
        // Verify the signature to check the messages supplied are valid
        if !(signature.verify::<_, _, X>(
            &pk,
            request.header.as_ref(),
            &generators,
            &digested_messages,
        )?) {
            return Err(Error::SignatureVerification);
        }
    }

    // Generate the proof
    let proof = Proof::new::<_, X>(
        &pk,
        &signature,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &proof_messages,
    )?;

    Ok(proof.to_octets())
}

// Verify a signature proof of knowledge.
pub(crate) fn proof_verify<T, X>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    X: ExpandMessage,
{
    // Parse public key from request
    let public_key = PublicKey::from_octets(request.public_key)?;

    // Digest the revealed proof messages
    let messages: BTreeMap<usize, Message> =
        digest_revealed_proof_messages::<_, X>(
            request.messages,
            request.total_message_count,
        )?;

    // Derive generators
    let generators = Generators::new::<X>(request.total_message_count)?;

    let proof = Proof::from_octets(request.proof)?;

    proof.verify::<_, X>(
        &public_key,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &messages,
    )
}
