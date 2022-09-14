mod api;

/// Core implementation of BBS scheme.
pub mod core;

pub use crate::schemes::bbs::api::dtos::{
    BbsBoundProofGenRequest,
    BbsBoundSignRequest,
    BbsBoundVerifyRequest,
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
};

/// BBS ciphersuites abstraction over core implementation.
pub mod ciphersuites;
