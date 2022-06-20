/// Sign request for a BBS signature
pub struct BbsSignRequest {
    /// Secret key
    pub secret_key: Vec<u8>,
    /// Public key
    pub public_key: Vec<u8>,
    /// Header containing context and application specific information
    pub header: Option<Vec<u8>>,
    /// Vector of messages to sign
    pub messages: Option<Vec<Vec<u8>>>,
}

/// Verify request for a BBS signature
pub struct BbsVerifyRequest {
    /// Public key
    pub public_key: Vec<u8>,
    /// Header containing context and application specific information
    pub header: Option<Vec<u8>>,
    /// Vector of messages to verify against a signature
    pub messages: Option<Vec<Vec<u8>>>,
    /// Signature to verify
    pub signature: Vec<u8>,
}

/// Sub structure for describing which messages to reveal in a derived proof
#[derive(Clone)]
pub struct BbsProofGenRevealMessageRequest {
    /// Indicates whether to reveal the current message in the derived proof
    pub reveal: bool,
    /// Value of the message
    pub value: Vec<u8>,
}

/// Derive proof request for computing a signature proof of knowledge for a
/// supplied BBS signature
pub struct BbsProofGenRequest {
    /// Public key associated to the BBS signature
    pub public_key: Vec<u8>,
    /// Header containing context and application specific information
    pub header: Option<Vec<u8>>,
    /// Vector of messages protected by the signature, including a flag
    /// indicating which to reveal in the derived proof
    pub messages: Option<Vec<BbsProofGenRevealMessageRequest>>,
    /// Signature to derive the signature proof of knowledge from
    pub signature: Vec<u8>,
    /// Presentation message to be bound to the signature proof of knowledge
    pub presentation_message: Option<Vec<u8>>,
}

/// Verify proof request for verifying a supplied signature proof of knowledge
pub struct BbsProofVerifyRequest {
    /// Public key associated to the signature proof of knowledge (who signed
    /// the original BBS signature the proof is derived from)
    pub public_key: Vec<u8>,
    /// Header containing context and application specific information
    pub header: Option<Vec<u8>>,
    /// Proof to verify
    pub proof: Vec<u8>,
    /// Presentation message associated to the signature proof of knowledge
    pub presentation_message: Option<Vec<u8>>,
    /// Total message count of the messages signed in the original signature
    /// (including unrevealed messages)
    pub total_message_count: usize,
    /// Revealed messages to validate against the signature proof of knowledge
    pub messages: Option<Vec<(usize, Vec<u8>)>>,
}
