use crate::curves::bls12_381::{
    OCTET_POINT_G1_LENGTH,
    OCTET_POINT_G2_LENGTH,
    OCTET_SCALAR_LENGTH,
};
pub use crate::schemes::bbs::{
    api::proof::get_proof_size,
    core::{
        constants::MIN_KEY_GEN_IKM_LENGTH,
        key_pair::{KeyPair, PublicKey, SecretKey},
    },
};

/// "SecretKey" length in bytes for "BBS_BLS12381G1" ciphersuite.
pub const BBS_BLS12381G1_SECRET_KEY_LENGTH: usize = OCTET_SCALAR_LENGTH;

/// "PublicKey" length in bytes for "BBS_BLS12381G1" ciphersuite.
pub const BBS_BLS12381G1_PUBLIC_KEY_LENGTH: usize = OCTET_POINT_G2_LENGTH;

/// "Signature" length in bytes for "BBS_BLS12381G1" ciphersuite.
pub const BBS_BLS12381G1_SIGNATURE_LENGTH: usize =
    OCTET_POINT_G1_LENGTH + 2 * OCTET_SCALAR_LENGTH;
