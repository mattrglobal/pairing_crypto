mod api;

/// Core implementation of BBS scheme.
pub mod core;

pub use crate::schemes::bbs::api::dtos::{
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
};

/// BBS ciphersuites abstraction over core implementation.
pub mod ciphersuites;
