use crate::curves::bls12_381::{G1Affine, G2Affine, Scalar};
use ff::PrimeField;

/// DST for messages.
/// TODO define properly for different type of messages
pub const APP_MESSAGE_DST: &[u8; 19] = b"BBS_SIG_MESSAGE_DST";

/// Secret key salt used for deriving keys in the BBS signature scheme
pub const BBS_SECRET_KEY_SALT: &[u8] = b"BBS-SIG-KEYGEN-SALT-";

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
