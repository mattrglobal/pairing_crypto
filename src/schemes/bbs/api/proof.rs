use super::{
    dtos::{BbsProofGenRequest, BbsProofVerifyRequest},
    utils::{
        digest_messages,
        digest_proof_messages,
        digest_revealed_proof_messages,
    },
};
use crate::{
    curves::bls12_381::hash_to_curve::{
        ExpandMessage,
        ExpandMsgXmd,
        ExpandMsgXof,
    },
    error::Error,
    schemes::bbs::core::{
        generator::Generators,
        key_pair::PublicKey,
        proof::Proof,
        signature::Signature,
        types::{Message, ProofMessage},
    },
};
use sha2::Sha256;
use sha3::Shake256;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

#[cfg(not(feature = "alloc"))]
use std::collections::BTreeMap;

/// Return the size of proof in bytes for `num_undisclosed_messages`.
pub fn get_proof_size(num_undisclosed_messages: usize) -> usize {
    Proof::get_size(num_undisclosed_messages)
}

/// Generate a BLS12-381-Shake-256 signature proof of knowledge.
pub fn proof_gen_shake_256<T>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    proof_gen::<_, ExpandMsgXof<Shake256>>(request)
}

/// Generate a BLS12-381-Sha-256 signature proof of knowledge.
pub fn proof_gen_sha_256<T>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    proof_gen::<_, ExpandMsgXmd<Sha256>>(request)
}

/// Verify a BLS12-381-Shake-256 signature proof of knowledge.
pub fn proof_verify_shake_256<T>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    proof_verify::<_, ExpandMsgXof<Shake256>>(request)
}

/// Verify a BLS12-381-Sha-256 signature proof of knowledge.
pub fn proof_verify_sha_256<T>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
{
    proof_verify::<_, ExpandMsgXmd<Sha256>>(request)
}

// Generate a signature proof of knowledge.
fn proof_gen<T, X>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
    X: ExpandMessage,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    let mut digested_messages = vec![];
    if let Some(request_messages) = request.messages {
        let request_messages = request_messages
            .iter()
            .map(|element| element.value.as_ref())
            .collect::<Vec<_>>();
        // Digest the supplied messages
        digested_messages = digest_messages::<_, X>(Some(&request_messages))?;
    }

    // Derive generators
    let generators = Generators::new::<X>(digested_messages.len())?;
    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    // Verify the signature to check the messages supplied are valid
    if !(signature.verify::<_, _, X>(
        &pk,
        request.header.as_ref(),
        &generators,
        &digested_messages,
    )?) {
        return Err(Error::SignatureVerification);
    }

    // Digest the supplied messages
    let messages: Vec<ProofMessage> =
        match digest_proof_messages::<_, X>(request.messages) {
            Ok(messages) => messages,
            Err(e) => return Err(e),
        };

    // Generate the proof
    let proof = Proof::new::<_, X>(
        &pk,
        &signature,
        request.header.as_ref(),
        request.presentation_message.as_ref(),
        &generators,
        &messages,
    )?;

    Ok(proof.to_octets())
}

// Verify a signature proof of knowledge.
pub fn proof_verify<T, X>(
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
        request.presentation_message.as_ref(),
        &generators,
        &messages,
    )
}
