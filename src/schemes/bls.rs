//! This module implements BLS signatures according to the IETF draft v4
//!
//! for the Proof of Possession Cipher Suite
//!
//! Since BLS signatures can use either G1 or G2 fields, there are two types of
//! public keys and signatures. Normal and Variant (suffix'd with Vt).
//!
//! Normal puts signatures in G1 and pubic keys in G2.
//! Variant is the reverse.
//!
//! This crate has been designed to be compliant with no-std by avoiding allocations
//!
//! but provides some optimizations when an allocator exists for verifying
//! aggregated signatures.

mod aggregate_signature;
mod aggregate_signature_vt;
mod multi_public_key;
mod multi_public_key_vt;
mod multi_signature;
mod multi_signature_vt;
mod proof_of_possession;
mod proof_of_possession_vt;
mod public_key;
mod public_key_vt;
mod secret_key;
mod signature;
mod signature_vt;

pub use aggregate_signature::*;
pub use aggregate_signature_vt::*;
pub use multi_public_key::*;
pub use multi_public_key_vt::*;
pub use multi_signature::*;
pub use multi_signature_vt::*;
pub use proof_of_possession::*;
pub use proof_of_possession_vt::*;
pub use public_key::*;
pub use public_key_vt::*;
pub use secret_key::*;
pub use signature::*;
pub use signature_vt::*;
