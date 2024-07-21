pub(crate) mod api;
pub use crate::schemes::bbs::api::dtos::{
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
};

// namespace bbs types
/// BBS related types
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
pub mod types {
    pub use crate::schemes::bbs::core::types::{
        ProofTrace,
        RandomScalars,
        SignatureTrace,
    };
}

// Core implementation of BBS scheme.
pub(crate) mod core;

/// BBS ciphersuites abstraction over core implementation.
pub mod ciphersuites;
