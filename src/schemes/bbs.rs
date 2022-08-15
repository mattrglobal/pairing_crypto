mod api;

/// Core implementation of BBS scheme.
pub mod core;

pub use crate::schemes::bbs::api::dtos::{
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
};

/// BBS ciphersuites abstraction over core implementation.
pub mod ciphersuites {
    /// BBS BLS-12-381 curve specific implementations.
    pub mod bls12_381 {
        pub use crate::schemes::bbs::{
            api::proof::get_proof_size,
            core::{
                constants::{
                    BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
                    BBS_BLS12381G1_SECRET_KEY_LENGTH,
                    BBS_BLS12381G1_SIGNATURE_LENGTH,
                    MIN_KEY_GEN_IKM_LENGTH,
                },
                key_pair::{KeyPair, PublicKey, SecretKey},
            },
        };
    }

    /// BBS BLS12-381-Shake-256 ciphersuites
    pub mod bls12_381_shake_256 {
        pub use crate::schemes::bbs::api::{
            proof::{
                proof_gen_shake_256 as proof_gen,
                proof_verify_shake_256 as proof_verify,
            },
            signature::{sign_shake_256 as sign, verify_shake_256 as verify},
        };
    }

    /// BBS BLS12-381-Sha-256 ciphersuites
    pub mod bls12_381_sha_256 {
        pub use crate::schemes::bbs::api::{
            proof::{
                proof_gen_sha_256 as proof_gen,
                proof_verify_sha_256 as proof_verify,
            },
            signature::{sign_sha_256 as sign, verify_sha_256 as verify},
        };
    }
}
