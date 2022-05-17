mod api;
mod message_generator;
mod pok_signature;
mod pok_signature_proof;
mod signature;

pub use message_generator::*;
pub use pok_signature::*;
pub use pok_signature_proof::*;
pub use signature::*;

pub use api::dtos::*;
pub use api::proof::derive as derive_proof;
pub use api::proof::verify as verify_proof;
pub use api::signature::sign;
pub use api::signature::verify;

/// Secret key salt used for deriving keys in the BBS signature scheme
pub const SECRET_KEY_SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";

pub use crate::curves::bls12_381::{PublicKey, SecretKey};
