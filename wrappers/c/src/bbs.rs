pub struct BbsSignRequestDto {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub header: Vec<u8>,
    pub messages: Vec<Vec<u8>>,
}

pub struct BbsVerifyRequestDto {
    pub public_key: Vec<u8>,
    pub header: Vec<u8>,
    pub messages: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}

pub struct BbsDeriveProofRevealMessageRequestDto {
    pub reveal: bool,
    pub value: Vec<u8>,
}

pub struct BbsDeriveProofRequestDto {
    pub public_key: Vec<u8>,
    pub header: Vec<u8>,
    pub messages: Vec<BbsDeriveProofRevealMessageRequestDto>,
    pub signature: Vec<u8>,
    pub presentation_header: Vec<u8>,
}

pub struct BbsVerifyProofRequestDto {
    pub public_key: Vec<u8>,
    pub header: Vec<u8>,
    pub proof: Vec<u8>,
    pub presentation_header: Vec<u8>,
    pub total_message_count: usize,
    pub messages: Vec<(usize, Vec<u8>)>,
}

/// Key generation API
pub mod key_gen;

/// BBS Sign API
pub mod sign;

/// BBS Verify API
pub mod verify;

/// BBS Get Proof Size API
pub mod get_proof_size;

/// BBS Proof Generation API
pub mod proof_gen;

/// BBS Proof Verify API
pub mod proof_verify;

// Re-export constants.
pub use pairing_crypto::bbs::ciphersuites::bls12_381::{
    BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
    BBS_BLS12381G1_SECRET_KEY_LENGTH,
    BBS_BLS12381G1_SIGNATURE_LENGTH,
};
