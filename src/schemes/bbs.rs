pub(crate) mod api;
pub use crate::schemes::bbs::api::dtos::{
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
};

// Core implementation of BBS scheme.
pub(crate) mod core;

/// BBS ciphersuites abstraction over core implementation.
pub mod ciphersuites;
