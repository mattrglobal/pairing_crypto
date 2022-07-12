use crate::bbs::core::constants::{
    BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
    BBS_BLS12381G1_SECRET_KEY_LENGTH,
    BBS_BLS12381G1_SIGNATURE_LENGTH,
};

/// Sign request for a BBS signature.
#[derive(Debug)]
pub struct BbsSignRequest<'a> {
    /// Secret key
    pub secret_key: &'a [u8; BBS_BLS12381G1_SECRET_KEY_LENGTH],
    /// Public key
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<&'a [u8]>,
    /// Vector of messages to sign
    pub messages: Option<&'a [&'a [u8]]>,
}

/// Verify request for a BBS signature.
#[derive(Debug)]
pub struct BbsVerifyRequest<'a> {
    /// Public key
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<&'a [u8]>,
    /// Vector of messages to verify against a signature
    pub messages: Option<&'a [&'a [u8]]>,
    /// Signature to verify
    pub signature: &'a [u8; BBS_BLS12381G1_SIGNATURE_LENGTH],
}

/// Sub structure for describing which messages to reveal in a derived proof.
#[derive(Clone, Debug)]
pub struct BbsProofGenRevealMessageRequest<'a> {
    /// Indicates whether to reveal the current message in the derived proof
    pub reveal: bool,
    /// Value of the message
    pub value: &'a [u8],
}

/// Derive proof request for computing a signature proof of knowledge for a
/// supplied BBS signature.
#[derive(Debug)]
pub struct BbsProofGenRequest<'a> {
    /// Public key associated to the BBS signature
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<&'a [u8]>,
    /// Vector of messages protected by the signature, including a flag
    /// indicating which to reveal in the derived proof
    pub messages: Option<&'a [BbsProofGenRevealMessageRequest<'a>]>,
    /// Signature to derive the signature proof of knowledge from
    pub signature: &'a [u8; BBS_BLS12381G1_SIGNATURE_LENGTH],
    /// Presentation message to be bound to the signature proof of knowledge
    pub presentation_message: Option<&'a [u8]>,
}

/// Verify proof request for verifying a supplied signature proof of knowledge.
#[derive(Debug)]
pub struct BbsProofVerifyRequest<'a> {
    /// Public key associated to the signature proof of knowledge (who signed
    /// the original BBS signature the proof is derived from)
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<&'a [u8]>,
    /// Proof to verify
    pub proof: &'a [u8],
    /// Presentation message associated to the signature proof of knowledge
    pub presentation_message: Option<&'a [u8]>,
    /// Total message count of the messages signed in the original signature
    /// (including unrevealed messages)
    pub total_message_count: usize,
    /// Revealed messages to validate against the signature proof of knowledge
    pub messages: Option<&'a [(usize, &'a [u8])]>,
}
