use crate::bbs::core::constants::{
    BBS_BLS12381G1_PUBLIC_KEY_LENGTH, BBS_BLS12381G1_SECRET_KEY_LENGTH,
    BBS_BLS12381G1_SIGNATURE_LENGTH,
};

/// Sign request for a BBS signature.
#[derive(Clone, Debug)]
pub struct BbsSignRequest<'a, T: AsRef<[u8]>> {
    /// Secret key
    pub secret_key: &'a [u8; BBS_BLS12381G1_SECRET_KEY_LENGTH],
    /// Public key
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<T>,
    /// Vector of messages to sign
    pub messages: Option<&'a [T]>,
}

impl<'a, T: AsRef<[u8]>> Default for BbsSignRequest<'a, T> {
    fn default() -> Self {
        Self {
            secret_key: &[0u8; BBS_BLS12381G1_SECRET_KEY_LENGTH],
            public_key: &[0u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
            header: Default::default(),
            messages: Default::default(),
        }
    }
}

/// Verify request for a BBS signature.
#[derive(Clone, Debug)]
pub struct BbsVerifyRequest<'a, T: AsRef<[u8]>> {
    /// Public key
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<T>,
    /// Vector of messages to verify against a signature
    pub messages: Option<&'a [T]>,
    /// Signature to verify
    pub signature: &'a [u8; BBS_BLS12381G1_SIGNATURE_LENGTH],
}

impl<'a, T: AsRef<[u8]>> Default for BbsVerifyRequest<'a, T> {
    fn default() -> Self {
        Self {
            public_key: &[0u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
            header: Default::default(),
            messages: Default::default(),
            signature: &[0u8; BBS_BLS12381G1_SIGNATURE_LENGTH],
        }
    }
}

/// Sub structure for describing which messages to reveal in a derived proof.
#[derive(Clone, Default, Debug)]
pub struct BbsProofGenRevealMessageRequest<T: AsRef<[u8]>> {
    /// Indicates whether to reveal the current message in the derived proof
    pub reveal: bool,
    /// Value of the message
    pub value: T,
}

/// Derive proof request for computing a signature proof of knowledge for a
/// supplied BBS signature.
#[derive(Clone, Debug)]
pub struct BbsProofGenRequest<'a, T: AsRef<[u8]>> {
    /// Public key associated to the BBS signature
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<T>,
    /// Vector of messages protected by the signature, including a flag
    /// indicating which to reveal in the derived proof
    pub messages: Option<&'a [BbsProofGenRevealMessageRequest<T>]>,
    /// Signature to derive the signature proof of knowledge from
    pub signature: &'a [u8; BBS_BLS12381G1_SIGNATURE_LENGTH],
    /// Presentation header to be bound to the signature proof of knowledge
    pub presentation_header: Option<T>,
    /// Flag which indicates if the signature verification should be done
    /// before actual proof computation.
    pub verify_signature: Option<bool>,
}

impl<'a, T: AsRef<[u8]>> Default for BbsProofGenRequest<'a, T> {
    fn default() -> Self {
        Self {
            public_key: &[0u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
            header: Default::default(),
            messages: Default::default(),
            signature: &[0u8; BBS_BLS12381G1_SIGNATURE_LENGTH],
            presentation_header: Default::default(),
            verify_signature: None,
        }
    }
}

/// Verify proof request for verifying a supplied signature proof of knowledge.
#[derive(Clone, Debug)]
pub struct BbsProofVerifyRequest<'a, T: AsRef<[u8]>> {
    /// Public key associated to the signature proof of knowledge (who signed
    /// the original BBS signature the proof is derived from)
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<T>,
    /// Presentation header associated to the signature proof of knowledge
    pub presentation_header: Option<T>,
    /// Proof to verify
    pub proof: &'a [u8],
    /// Total message count of the messages signed in the original signature
    /// (including unrevealed messages)
    pub total_message_count: usize,
    /// Revealed messages to validate against the signature proof of knowledge
    pub messages: Option<&'a [(usize, T)]>,
}

impl<'a, T: AsRef<[u8]>> Default for BbsProofVerifyRequest<'a, T> {
    fn default() -> Self {
        Self {
            public_key: &[0u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
            header: Default::default(),
            messages: Default::default(),
            presentation_header: Default::default(),
            proof: &[0u8; 0],
            total_message_count: Default::default(),
        }
    }
}
