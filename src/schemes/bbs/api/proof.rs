use super::{
    dtos::{
        BbsBoundProofGenRequest,
        BbsProofGenRequest,
        BbsProofVerifyRequest,
    },
    utils::{digest_proof_messages, digest_revealed_proof_messages},
};
use crate::{
    bbs::{
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

// Generate a BBS signature proof of knowledge.
pub(crate) fn proof_gen<T, C>(
    request: &BbsProofGenRequest<'_, T>,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse public key from request
    let pk = PublicKey::from_octets(request.public_key)?;

    let (digested_messages, proof_messages) =
        digest_proof_messages::<_, C>(request.messages)?;

    // Derive generators
    let generators =
        MemoryCachedGenerators::<C>::new(digested_messages.len(), 0)?;
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

// Generate a BBS bound signature proof of knowledge.
pub(crate) fn bound_proof_gen<T, C>(
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
        digest_proof_messages::<_, C>(request.messages)?;
    digested_messages.push(bls_sk);
    proof_messages.push(ProofMessage::Hidden(bls_sk));

    // Derive generators
    let generators =
        MemoryCachedGenerators::<C>::new(digested_messages.len() - 1, 1)?;

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

// Verify a BBS signature proof of knowledge.
pub(crate) fn proof_verify<T, C>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    do_proof_verify::<_, C>(request, false)
}

// Verify a BBS bound signature proof of knowledge.
pub(crate) fn bound_proof_verify<T, C>(
    request: &BbsProofVerifyRequest<'_, T>,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    do_proof_verify::<_, C>(request, true)
}

// Verify a BBS signature proof of knowledge.
pub(crate) fn do_proof_verify<T, C>(
    request: &BbsProofVerifyRequest<'_, T>,
    private_holder_binding: bool,
) -> Result<bool, Error>
where
    T: AsRef<[u8]>,
    C: BbsCiphersuiteParameters,
{
    // Parse public key from request
    let public_key = PublicKey::from_octets(request.public_key)?;

    // Digest the revealed proof messages
    let messages: BTreeMap<usize, Message> =
        digest_revealed_proof_messages::<_, C>(
            request.messages,
            request.total_message_count,
        )?;

    // Derive generators
    let mut total_message_count = request.total_message_count;
    let mut extension_count = 0;
    if private_holder_binding {
        total_message_count -= 1;
        extension_count = 1;
    }
    let mut generators =
        MemoryCachedGenerators::<C>::new(total_message_count, extension_count)?;

    let proof = Proof::from_octets(request.proof)?;

    proof.verify::<_, _, C>(
        &public_key,
        request.header.as_ref(),
        request.presentation_header.as_ref(),
        &mut generators,
        &messages,
    )
}
