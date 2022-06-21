use crate::dtos::{BbsSignRequestDto, ByteArray, PairingCryptoFfiError};
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs::ciphersuites::bls12_381::{sign, BbsSignRequest};

lazy_static! {
    pub static ref BBS_SIGN_CONTEXT: ConcurrentHandleMap<BbsSignRequestDto> =
        ConcurrentHandleMap::new();
}

#[no_mangle]
pub extern "C" fn bls12381_bbs_sign_context_init(err: &mut ExternError) -> u64 {
    BBS_SIGN_CONTEXT.insert_with_output(err, || BbsSignRequestDto {
        secret_key: Vec::new(),
        public_key: Vec::new(),
        header: Vec::new(),
        messages: Vec::new(),
    })
}

set_byte_array_impl!(
    bls12381_bbs_sign_context_set_secret_key,
    BBS_SIGN_CONTEXT,
    secret_key
);

set_byte_array_impl!(
    bls12381_bbs_sign_context_set_public_key,
    BBS_SIGN_CONTEXT,
    public_key
);

set_byte_array_impl!(
    bls12381_bbs_sign_context_set_header,
    BBS_SIGN_CONTEXT,
    header
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
                return Err(PairingCryptoFfiError::new(
                    "Secret Key must be set",
                ));
            }
            if ctx.public_key.is_empty() {
                return Err(PairingCryptoFfiError::new(
                    "Public Key must be set",
                ));
            }

            let header = if ctx.header.is_empty() {
                None
            } else {
                Some(ctx.header.clone())
            };

            let messages = if ctx.messages.is_empty() {
                None
            } else {
                Some(ctx.messages.clone())
            };

            let s = sign(BbsSignRequest {
                secret_key: ctx.secret_key.clone(),
                public_key: ctx.public_key.clone(),
                header,
                messages,
            })?;
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
