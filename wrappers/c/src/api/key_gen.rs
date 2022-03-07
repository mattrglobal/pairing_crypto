use crate::dtos::ByteArray;
use ffi_support::{ByteBuffer, ExternError};
use pairing_crypto::bls12_381::bbs::SECRET_KEY_SALT;
use pairing_crypto::bls12_381::{PublicKey, PublicKeyVt, SecretKey};

/// Generate a BLS 12-381 key pair in the G1 field.
///
/// * seed: UIntArray with 32 elements
///
/// returned vector is the concatenation of first the private key (32 bytes)
/// followed by the public key (48) bytes.
#[no_mangle]
pub extern "C" fn bls12381_generate_g1_key(
    seed: ByteArray,
    public_key: &mut ByteBuffer,
    secret_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    // Derive secret key from supplied seed otherwise generate a new seed and a derive a key from this
    // using the underlying RNG usually defaults to the OS provided RNG e.g in Node is node crypto
    let sk = SecretKey::new(SECRET_KEY_SALT, seed.to_opt_vec()).unwrap();

    // Derive the public key from the secret key
    let pk = PublicKey::from(&sk);

    *public_key = ByteBuffer::from_vec(pk.to_bytes().to_vec());
    *secret_key = ByteBuffer::from_vec(sk.to_bytes().to_vec());
    *err = ExternError::success();
    0
}

/// Generate a BLS 12-381 key pair in the G2 field.
///
/// * seed: UIntArray with 32 elements
///
/// Returned value is a byte array which is the concatenation of first the private key (32 bytes)
/// followed by the public key (96) bytes.
#[no_mangle]
pub extern "C" fn bls12381_generate_g2_key(
    seed: ByteArray,
    public_key: &mut ByteBuffer,
    secret_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    // Derive secret key from supplied seed otherwise generate a new seed and a derive a key from this
    // using the underlying RNG usually defaults to the OS provided RNG e.g in Node is node crypto
    let sk = SecretKey::new(SECRET_KEY_SALT, seed.to_opt_vec()).unwrap();

    // Derive the public key from the secret key
    let pk = PublicKeyVt::from(&sk);

    *public_key = ByteBuffer::from_vec(pk.to_bytes().to_vec());
    *secret_key = ByteBuffer::from_vec(sk.to_bytes().to_vec());
    *err = ExternError::success();
    0
}
