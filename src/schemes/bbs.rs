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

/// BBS Interface abstraction over ciphersuites, defining how messages are
/// mapped to scalars, how generators are created and how core interfaces are
/// used.
pub mod interface;

/// Calculating the generators, that form part of the BBS Signature
/// public parameters.
pub mod generator;
