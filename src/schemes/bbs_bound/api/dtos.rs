use crate::{
    bbs::ciphersuites::bls12_381::{
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
        BBS_BLS12381G1_SECRET_KEY_LENGTH,
        BBS_BLS12381G1_SIGNATURE_LENGTH,
    },
    bls::ciphersuites::bls12_381::{
        BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH,
        BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH,
        BLS_SIG_BLS12381G2_SIGNATURE_LENGTH,
    },
};

// #TODO make hardcodeds length a generic const

/// Request to generate a proof of posession commitment for a BLS secret key.
#[derive(Clone, Debug)]
pub struct BlsKeyPopGenRequest<'a> {
    /// BLS Secret key
    pub bls_secret_key: &'a [u8; BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH],
    /// The Issuer's unique identifier
    pub aud: &'a [u8],
    /// Domain separation tag. If not supplied it defaults to the empty string
    /// ("")
    pub dst: Option<&'a [u8]>,
    /// Extra information to bind to a KeyPoP (e.g., creation date, dst etc.).
    /// If not supplied, it defaults to the empty string ("").
    pub extra_info: Option<&'a [u8]>,
}

impl<'a> Default for BlsKeyPopGenRequest<'a> {
    fn default() -> Self {
        Self {
            bls_secret_key: &[0u8; BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH],
            aud: &[0u8; 0],
            dst: Default::default(),
            extra_info: Default::default(),
        }
    }
}

/// Request to validate a proof of posession commitment for a BLS secret key.
#[derive(Clone, Debug)]
pub struct BlsKeyPopVerifyRequest<'a> {
    /// BLS Key-Pop
    pub bls_key_pop: &'a [u8; BLS_SIG_BLS12381G2_SIGNATURE_LENGTH],
    /// BLS Public key
    pub bls_public_key: &'a [u8; BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH],
    /// The Issuer's unique identifier
    pub aud: &'a [u8],
    /// Domain separation tag. If not supplied it defaults to the empty string
    /// ("")
    pub dst: Option<&'a [u8]>,
    /// Extra information to bind to a KeyPoP (e.g., creation date, dst etc.).
    /// If not supplied, it defaults to the empty string ("").
    pub extra_info: Option<&'a [u8]>,
}

impl<'a> Default for BlsKeyPopVerifyRequest<'a> {
    fn default() -> Self {
        Self {
            bls_key_pop: &[0u8; BLS_SIG_BLS12381G2_SIGNATURE_LENGTH],
            bls_public_key: &[0u8; BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH],
            aud: &[0u8; 0],
            dst: Default::default(),
            extra_info: Default::default(),
        }
    }
}

/// Sign request for a bound BBS signature.
#[derive(Clone, Debug)]
pub struct BbsBoundSignRequest<'a, T: AsRef<[u8]>> {
    /// Secret key
    pub secret_key: &'a [u8; BBS_BLS12381G1_SECRET_KEY_LENGTH],
    /// Public key
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// BLS Public key
    pub bls_public_key: &'a [u8; BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<T>,
    /// Vector of messages to sign
    pub messages: Option<&'a [T]>,
}

impl<'a, T: AsRef<[u8]>> Default for BbsBoundSignRequest<'a, T> {
    fn default() -> Self {
        Self {
            secret_key: &[0u8; BBS_BLS12381G1_SECRET_KEY_LENGTH],
            public_key: &[0u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
            bls_public_key: &[0u8; BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH],
            header: Default::default(),
            messages: Default::default(),
        }
    }
}

/// Verify request for a bound BBS signature.
#[derive(Clone, Debug)]
pub struct BbsBoundVerifyRequest<'a, T: AsRef<[u8]>> {
    /// Public key
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// BLS Secret key
    pub bls_secret_key: &'a [u8; BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<T>,
    /// Vector of messages to verify against a signature
    pub messages: Option<&'a [T]>,
    /// Signature to verify
    pub signature: &'a [u8; BBS_BLS12381G1_SIGNATURE_LENGTH],
}

impl<'a, T: AsRef<[u8]>> Default for BbsBoundVerifyRequest<'a, T> {
    fn default() -> Self {
        Self {
            public_key: &[0u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
            bls_secret_key: &[0u8; BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH],
            header: Default::default(),
            messages: Default::default(),
            signature: &[0u8; BBS_BLS12381G1_SIGNATURE_LENGTH],
        }
    }
}

/// Sub structure for describing which messages to reveal in a derived proof.
#[derive(Clone, Default, Debug)]
pub struct BbsBoundProofGenRevealMessageRequest<T: AsRef<[u8]>> {
    /// Indicates whether to reveal the current message in the derived proof
    pub reveal: bool,
    /// Value of the message
    pub value: T,
}

/// Derive proof request for computing a signature proof of knowledge for a
/// supplied BBS signature.
#[derive(Clone, Debug)]
pub struct BbsBoundProofGenRequest<'a, T: AsRef<[u8]>> {
    /// Public key associated to the BBS signature
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// BLS Secret key
    pub bls_secret_key: &'a [u8; BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<T>,
    /// Vector of messages protected by the signature, including a flag
    /// indicating which to reveal in the derived proof
    pub messages: Option<&'a [BbsBoundProofGenRevealMessageRequest<T>]>,
    /// Signature to derive the signature proof of knowledge from
    pub signature: &'a [u8; BBS_BLS12381G1_SIGNATURE_LENGTH],
    /// Presentation header to be bound to the signature proof of knowledge
    pub presentation_header: Option<T>,
    /// Flag which indicates if the signature verification should be done
    /// before actual proof computation.
    pub verify_signature: Option<bool>,
}

impl<'a, T: AsRef<[u8]>> Default for BbsBoundProofGenRequest<'a, T> {
    fn default() -> Self {
        Self {
            public_key: &[0u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
            bls_secret_key: &[0u8; BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH],
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
pub struct BbsBoundProofVerifyRequest<'a, T: AsRef<[u8]>> {
    /// Public key associated to the signature proof of knowledge (who signed
    /// the original BBS signature the proof is derived from)
    pub public_key: &'a [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
    /// Header containing context and application specific information
    pub header: Option<T>,
    /// Presentation header associated to the signature proof of knowledge
    pub presentation_header: Option<T>,
    /// Proof to verify
    pub proof: &'a [u8],
    /// Revealed messages to validate against the signature proof of knowledge
    pub messages: Option<&'a [(usize, T)]>,
}

impl<'a, T: AsRef<[u8]>> Default for BbsBoundProofVerifyRequest<'a, T> {
    fn default() -> Self {
        Self {
            public_key: &[0u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
            header: Default::default(),
            messages: Default::default(),
            presentation_header: Default::default(),
            proof: &[0u8; 0],
        }
    }
}
