use crate::dtos::{ByteArray, PairingCryptoFfiError, VerifyContext};
use ffi_support::{ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bls12_381::PublicKey;
use pairing_crypto::schemes::bbs::{MessageGenerators, Signature};
use pairing_crypto::schemes::core::Message;

lazy_static! {
    pub static ref VERIFY_CONTEXT: ConcurrentHandleMap<VerifyContext> = ConcurrentHandleMap::new();
}

#[no_mangle]
pub extern "C" fn bls12381_bbs_verify_context_init(err: &mut ExternError) -> u64 {
    VERIFY_CONTEXT.insert_with_output(err, || VerifyContext {
        messages: Vec::new(),
        public_key: None,
        signature: None,
    })
}

add_set_key_bytes_impl!(
    bls12381_bbs_verify_context_set_public_key,
    VERIFY_CONTEXT,
    public_key,
    PublicKey
);

add_set_message_bytes_impl!(
    bls12381_bbs_verify_context_set_message,
    VERIFY_CONTEXT // TODO can probably generalize this more
);

// TODO ..??
add_set_key_bytes_impl!(
    bls12381_bbs_verify_context_set_signature,
    VERIFY_CONTEXT,
    signature,
    Signature
);

#[no_mangle]
pub extern "C" fn bls12381_bbs_verify_context_finish(handle: u64, err: &mut ExternError) -> i32 {
    VERIFY_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<i32, PairingCryptoFfiError> {
            if ctx.public_key.is_none() {
                return Err(PairingCryptoFfiError::new("Public Key must be set"));
            }
            if ctx.messages.is_empty() {
                return Err(PairingCryptoFfiError::new("Messages cannot be empty"));
            }
            if ctx.signature.is_none() {
                return Err(PairingCryptoFfiError::new("Signature must be set"));
            }

            match (ctx.signature.as_ref(), ctx.public_key.as_ref()) {
                (Some(ref sig), Some(ref pk)) => {
                    // Use generators derived from the signers public key
                    // TODO this approach is likely to change soon
                    let generators = MessageGenerators::from_public_key(**pk, ctx.messages.len());

                    match sig.verify(pk, &generators, ctx.messages.as_slice()) {
                        true => Ok(0),
                        false => Ok(1),
                    }
                }
                (_, _) => Err(PairingCryptoFfiError::new("")),
            }
        },
    )
}

define_handle_map_deleter!(VERIFY_CONTEXT, bls12381_bbs_verify_free);
