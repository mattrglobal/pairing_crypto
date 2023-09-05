use super::{
    dtos::{BbsBoundProofGenRequest, BbsBoundProofVerifyRequest},
    utils::digest_bound_proof_messages,
};
use crate::{
    bbs::{
        api::utils::digest_revealed_proof_messages,
        ciphersuites::BbsCiphersuiteParameters,
        core::{
            generator::memory_cached_generator::MemoryCachedGenerators,
            types::ProofMessage,
        },
    },
    error::Error,
    schemes::bbs::core::{
        key_pair::PublicKey,
        proof::Proof,
        signature::Signature,
        types::Message,
    },
};

use crate::bls::core::key_pair::SecretKey as BlsSecretKey;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

#[cfg(not(feature = "alloc"))]
use std::collections::BTreeMap;

/// Return the size of proof in bytes for `num_undisclosed_messages`.
pub fn get_proof_size(num_undisclosed_messages: usize) -> usize {
    Proof::get_size(num_undisclosed_messages)
}

// Generate a BBS bound signature proof of knowledge.
pub(crate) fn proof_gen<T, C>(
    request: &BbsBoundProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    // Parse BLS secret key from request
    let bls_sk = BlsSecretKey::from_bytes(request.bls_secret_key)?;
    let bls_sk = Message(*bls_sk.0);

    let (mut digested_messages, mut proof_messages) =
        digest_bound_proof_messages::<_, C>(request.messages)?;
    digested_messages.push(bls_sk);
    proof_messages.push(ProofMessage::Hidden(bls_sk));

    // Derive generators
    let generators = MemoryCachedGenerators::<C>::new(
        digested_messages.len() - 1,
        Some(true),
    )?;

    // Parse signature from request
    let signature = Signature::from_octets(request.signature)?;

    let verify_signature = request.verify_signature.unwrap_or(true);
    if verify_signature {
        // Verify the signature to check the messages supplied are valid
        if !(signature.verify::<_, _, _, C>(
            &pk,
            request.header.as_ref(),
            &generators,
            &digested_messages,
        )?) {
            return Err(Error::SignatureVerification);
        }
    }

    // Generate the proof
    let proof = Proof::new::<_, _, C>(
        &pk,
        &signature,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &proof_messages,
    )?;

    Ok(proof.to_octets())
}

// Verify a BBS bound signature proof of knowledge.
pub(crate) fn proof_verify<T, C>(
    request: &BbsBoundProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse public key from request
    let public_key = PublicKey::from_octets(request.public_key)?;

    // Parse proof from request
    let proof = Proof::from_octets(request.proof)?;

    // Deserialize the messages
    let messages = request.messages.unwrap_or(&[] as &[(usize, T)]);

    // Calculate total messages count
    let total_message_count = proof.m_hat_list.len() + messages.len();

    // Digest the revealed proof messages
    let messages: BTreeMap<usize, Message> =
        digest_revealed_proof_messages::<_, C>(messages, total_message_count)?;

    // Derive generators
    let generators = MemoryCachedGenerators::<C>::new(
        total_message_count - 1, /* total_message_count also includes the
                                  * prover's commitment */
        Some(true),
    )?;

    proof.verify::<_, _, C>(
        &public_key,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &generators,
        &messages,
        // Some(total_message_count),
    )
}
