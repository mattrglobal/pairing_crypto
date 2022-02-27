use crate::dtos::{ByteArray, PairingCryptoFfiError, SignContext};
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bls12_381::{PublicKey, SecretKey};
use pairing_crypto::schemes::bbs::{MessageGenerators, Signature};
use pairing_crypto::schemes::core::Message;
lazy_static! {
    pub static ref SIGN_CONTEXT: ConcurrentHandleMap<SignContext> = ConcurrentHandleMap::new();
}

#[no_mangle]
pub extern "C" fn bls12381_bbs_sign_context_init(err: &mut ExternError) -> u64 {
    SIGN_CONTEXT.insert_with_output(err, || SignContext {
        messages: Vec::new(),
        secret_key: None,
        signature: None,
    })
}

add_set_key_bytes_impl!(
    bls12381_bbs_sign_context_set_secret_key,
    SIGN_CONTEXT,
    secret_key,
    SecretKey
);

add_set_message_bytes_impl!(
    bls12381_bbs_sign_context_set_message,
    SIGN_CONTEXT // TODO can probably generalize this more
);

#[no_mangle]
pub extern "C" fn bls12381_bbs_sign_context_finish(
    handle: u64,
    signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let sig = SIGN_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<ByteBuffer, PairingCryptoFfiError> {
            if ctx.secret_key.is_none() {
                return Err(PairingCryptoFfiError::new("Secret Key must be set"));
            }
            if ctx.messages.is_empty() {
                return Err(PairingCryptoFfiError::new("Messages cannot be empty"));
            }

            match ctx.secret_key.as_ref() {
                Some(ref sk) => {
                    // Derive the public key from the secret key
                    let pk = PublicKey::from(*sk);

                    // Use generators derived from the signers public key
                    // TODO this approach is likely to change soon
                    let generators = MessageGenerators::from_public_key(pk, ctx.messages.len());

                    // TODO review this
                    let s = Signature::new(sk, &generators, ctx.messages.as_slice())?;
                    Ok(ByteBuffer::from_vec(s.to_bytes().to_vec()))
                }
                _ => Ok(ByteBuffer::new_with_size(0)),
            }
        },
    );

    if err.get_code().is_success() {
        *signature = sig;
        if let Err(e) = SIGN_CONTEXT.remove_u64(handle) {
            *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e))
        }
    }
    err.get_code().code()
}

define_handle_map_deleter!(SIGN_CONTEXT, bls12381_bbs_sign_free);
