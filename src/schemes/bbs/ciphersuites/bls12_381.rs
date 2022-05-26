pub use crate::schemes::bbs::core::{
    constants::{
        g1_affine_compressed_size,
        g2_affine_compressed_size,
        scalar_size,
    },
    message_generator::*,
    pok_signature::*,
    pok_signature_proof::*,
    proof_committed_builder::ProofCommittedBuilder,
    public_key::PublicKey,
    secret_key::SecretKey,
    signature::*,
    types::{
        Challenge,
        Commitment,
        HiddenMessage,
        Message,
        Nonce,
        PresentationMessage,
        ProofMessage,
        SignatureBlinding,
    },
};

pub use crate::schemes::bbs::api::{
    dtos::*,
    proof::{derive as derive_proof, verify as verify_proof},
    signature::{sign, verify},
};

/// Secret key salt used for deriving keys in the BBS signature scheme
pub const SECRET_KEY_SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";
