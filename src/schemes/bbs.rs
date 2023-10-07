pub(crate) mod api;
pub use crate::schemes::bbs::api::dtos::{
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
};

pub use crate::schemes::bbs::core::types::{ProofTrace, SignatureTrace};

// Core implementation of BBS scheme.
pub(crate) mod core;

/// BBS ciphersuites abstraction over core implementation.
pub mod ciphersuites;
