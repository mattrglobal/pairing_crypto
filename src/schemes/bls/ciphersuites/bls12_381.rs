use crate::curves::bls12_381::{
    OCTET_POINT_G1_LENGTH,
    OCTET_POINT_G2_LENGTH,
    OCTET_SCALAR_LENGTH,
};

pub use crate::schemes::bls::core::{
    constants::MIN_KEY_GEN_IKM_LENGTH,
    key_pair::{KeyPair, PublicKey, SecretKey},
};

/// "SecretKey" length in bytes for "BLS_SIG_BLS12381G2" ciphersuite.
pub const BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH: usize = OCTET_SCALAR_LENGTH;

/// "PublicKey" length in bytes for "BLS_SIG_BLS12381G2" ciphersuite.
pub const BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH: usize = OCTET_POINT_G1_LENGTH;

/// "Signature" length in bytes for "BLS_SIG_BLS12381G2" ciphersuite.
pub const BLS_SIG_BLS12381G2_SIGNATURE_LENGTH: usize = OCTET_POINT_G2_LENGTH;
