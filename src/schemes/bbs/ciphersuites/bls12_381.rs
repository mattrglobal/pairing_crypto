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
    OCTET_POINT_G1_LENGTH + OCTET_SCALAR_LENGTH;

/// "Export" the suite specific constants for the fixtures generation tool.
#[cfg(feature = "__private_bbs_fixtures_generator_api")]
#[cfg_attr(docsrs, doc(cfg(feature = "__private_bbs_fixtures_generator_api")))]
pub mod suite_constants {
    pub use crate::curves::bls12_381::{
        OCTET_POINT_G1_LENGTH,
        OCTET_POINT_G2_LENGTH,
        OCTET_SCALAR_LENGTH,
    };

    /// Number of random bytes required when creating random scalars.
    pub const BBS_BLS12381G1_EXPAND_LEN: usize = 48usize;
}
