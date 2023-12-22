pub(crate) mod api;
pub use crate::schemes::bbs::api::dtos::{
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
};

pub use crate::schemes::bbs::core::{
    proof::RandomScalars,
    types::{ProofTrace, SignatureTrace},
};

pub use crate::curves::bls12_381;

// Core implementation of BBS scheme.
pub(crate) mod core;

/// BBS ciphersuites abstraction over core implementation.
pub mod ciphersuites;
