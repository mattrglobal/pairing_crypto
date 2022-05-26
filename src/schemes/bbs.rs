mod api;

/// Core implementation of BBS scheme.
#[macro_use]
pub mod core;

pub use api::{
    dtos::*,
    proof::{derive as derive_proof, verify as verify_proof},
    signature::{sign, verify},
};

/// Secret key salt used for deriving keys in the BBS signature scheme
pub const SECRET_KEY_SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";
