mod api;

/// Core implementation of BBS scheme.
#[macro_use]
pub mod core;

pub use api::dtos::*;
pub use api::proof::derive as derive_proof;
pub use api::proof::verify as verify_proof;
pub use api::signature::sign;
pub use api::signature::verify;

/// Secret key salt used for deriving keys in the BBS signature scheme
pub const SECRET_KEY_SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";
