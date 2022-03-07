use crate::dtos::{BbsSignRequestDto, ByteArray, PairingCryptoFfiError};
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bls12_381::bbs::*;
lazy_static! {
    pub static ref BBS_SIGN_CONTEXT: ConcurrentHandleMap<BbsSignRequestDto> =
        ConcurrentHandleMap::new();
}

#[no_mangle]
pub extern "C" fn bls12381_bbs_sign_context_init(err: &mut ExternError) -> u64 {
    BBS_SIGN_CONTEXT.insert_with_output(err, || BbsSignRequestDto {
        messages: Vec::new(),
        secret_key: Vec::new(),
    })
}

set_byte_array_impl!(
    bls12381_bbs_sign_context_set_secret_key,
    BBS_SIGN_CONTEXT,
    secret_key
);

add_byte_array_impl!(
    bls12381_bbs_sign_context_add_message,
    BBS_SIGN_CONTEXT,
    messages
);

#[no_mangle]
pub extern "C" fn bls12381_bbs_sign_context_finish(
    handle: u64,
    signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let sig = BBS_SIGN_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<ByteBuffer, PairingCryptoFfiError> {
            if ctx.secret_key.is_empty() {
                return Err(PairingCryptoFfiError::new("Secret Key must be set"));
            }
            if ctx.messages.is_empty() {
                return Err(PairingCryptoFfiError::new("Messages cannot be empty"));
            }

            let s = sign(BbsSignRequest {
                secret_key: ctx.secret_key.clone(),
                messages: ctx.messages.clone(),
            })
            .unwrap();
            Ok(ByteBuffer::from_vec(s.to_vec()))
        },
    );

    if err.get_code().is_success() {
        *signature = sig;
        if let Err(e) = BBS_SIGN_CONTEXT.remove_u64(handle) {
            *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e))
        }
    }
    err.get_code().code()
}

define_handle_map_deleter!(BBS_SIGN_CONTEXT, bls12381_bbs_sign_free);
