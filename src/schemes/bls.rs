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
mod signature;
mod signature_vt;

/// Secret key salt used for deriving keys in the BBS signature scheme
pub const SECRET_KEY_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";

pub use aggregate_signature::*;
pub use aggregate_signature_vt::*;
pub use multi_public_key::*;
pub use multi_public_key_vt::*;
pub use multi_signature::*;
pub use multi_signature_vt::*;
pub use proof_of_possession::*;
pub use proof_of_possession_vt::*;
pub use signature::*;
pub use signature_vt::*;
