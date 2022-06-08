use crate::curves::bls12_381::{G1Affine, G2Affine, Scalar};
use ff::PrimeField;

/// BLS12-381 Ciphersuite ID.
pub const BBS_CIPHERSUITE_ID: &[u8; 37] =
    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";

/// DST for messages.
/// TODO define properly for different type of messages
pub const APP_MESSAGE_DST: &[u8; 19] = b"BBS_SIG_MESSAGE_DST";

/// Secret key salt used for deriving keys in the BBS signature scheme
pub const BBS_SECRET_KEY_SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";

/// A seed value with global scope for `message_generator_seed` as defined in
/// BBS signature Spec which is used by the CreateGenerators operation to
/// compute the required set of message generators.
pub const GLOBAL_MESSAGE_GENERATOR_SEED: &[u8] =
    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_MESSAGE_GENERATOR_SEED";

/// A seed value with global scope for `blind_value_generator_seed` as defined
/// in BBS signature Spec which is used by the which is used by the
/// CreateGenerators operation to compute the signature blinding value generator
/// (H_s).
pub const GLOBAL_BLIND_VALUE_GENERATOR_SEED: &[u8] =
    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_BLINDING_GENERATOR_SEED";

/// A seed value with global scope for `sig_domain_generator_seed` as defined
/// in BBS signature Spec which is used by the CreateGenerators operation to
/// compute the generator used to sign the signature domain separation tag
/// (H_d).
pub const GLOBAL_SIG_DOMAIN_GENERATOR_SEED: &[u8] =
    b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_DOMAIN_GENERATOR_SEED";

/// DST for `hash_to_curve` operation in G1.
pub const HASH_TO_CURVE_G1_DST: &[u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO";

/// Number of bytes to draw from the xof when performing operations such as
/// creating generators or computing the e and s components of the signature.
pub const XOF_NO_OF_BYTES: usize = 64usize;

/// Number of bytes to store a scalar.
pub const fn scalar_size() -> usize {
    (Scalar::NUM_BITS as usize + 8 - 1) / 8
}

/// Number of bytes to store an element of G1 in affine and compressed form.
pub const fn g1_affine_compressed_size() -> usize {
    G1Affine::compressed_size()
}

/// Number of bytes to store an element of G2 in affine and compressed form.
pub const fn g2_affine_compressed_size() -> usize {
    G2Affine::compressed_size()
}
