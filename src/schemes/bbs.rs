mod api;
mod message_generator;
mod pok_signature;
mod pok_signature_proof;
mod public_key;
mod secret_key;
mod signature;

mod ciphersuites;

/// Common methods and structs for all schemes
#[macro_use]
pub mod core;

pub use message_generator::*;
pub use pok_signature::*;
pub use pok_signature_proof::*;
pub use public_key::PublicKey;
pub use secret_key::SecretKey;
pub use signature::*;

pub use api::dtos::*;
pub use api::proof::derive as derive_proof;
pub use api::proof::verify as verify_proof;
pub use api::signature::sign;
pub use api::signature::verify;

/// Secret key salt used for deriving keys in the BBS signature scheme
pub const SECRET_KEY_SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";
