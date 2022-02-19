mod issuer;
mod message_generator;
mod pok_signature;
mod pok_signature_proof;
mod prover;
mod signature;
mod verifier;

pub use issuer::*;
pub use message_generator::*;
pub use pok_signature::*;
pub use pok_signature_proof::*;
pub use prover::*;
pub use signature::*;
pub use verifier::*;

/// Secret key salt used for deriving keys in the BBS signature scheme
pub const SECRET_KEY_SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";

pub use crate::curves::bls12_381::{PublicKey, SecretKey};
pub use crate::schemes::bls::ProofOfPossession;
