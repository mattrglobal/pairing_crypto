#![deny(
warnings,
missing_docs,
unsafe_code,
unused_import_braces,
unused_lifetimes,
unused_qualifications,
)]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]
//! This implements the hash to curve as described in
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1>
//!
//! The idea is to offer concrete methods for hashing arbitrary input to a point on an
//! elliptic curve used in cryptography.
//!
//! As much as possible, the interfaces, structs, and traits have been modeled after
//! the RustCrypto `digest` crate at <https://docs.rs/digest/>
//!
//! These methods do not cover serialization or deserialization according to
//! <http://www.secg.org/sec1-v2.pdf>

pub trait ClearH {
    fn clear_h(&mut self);
}


/// Computes sgn0
pub mod signum;
/// Compute hash to field using a specified digest
pub mod hash_to_field;