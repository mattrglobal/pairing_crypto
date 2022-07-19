use crate::dtos::{BbsVerifyRequestDto, ByteArray, PairingCryptoFfiError};
use core::convert::TryFrom;
use ffi_support::{ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs::ciphersuites::bls12_381::{
    verify,
    BbsVerifyRequest,
    BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
    BBS_BLS12381G1_SIGNATURE_LENGTH,
};

lazy_static! {
    pub static ref BBS_VERIFY_CONTEXT: ConcurrentHandleMap<BbsVerifyRequestDto> =
        ConcurrentHandleMap::new();
}

#[no_mangle]
pub extern "C" fn bls12381_bbs_verify_context_init(
    err: &mut ExternError,
) -> u64 {
    BBS_VERIFY_CONTEXT.insert_with_output(err, || BbsVerifyRequestDto {
        public_key: Vec::new(),
        header: Vec::new(),
        messages: Vec::new(),
        signature: Vec::new(),
    })
}

set_byte_array_impl!(
    bls12381_bbs_verify_context_set_public_key,
    BBS_VERIFY_CONTEXT,
    public_key
);

set_byte_array_impl!(
    bls12381_bbs_verify_context_set_header,
    BBS_VERIFY_CONTEXT,
    header
);

add_byte_array_impl!(
    bls12381_bbs_verify_context_set_message,
    BBS_VERIFY_CONTEXT,
    messages
);

set_byte_array_impl!(
    bls12381_bbs_verify_context_set_signature,
    BBS_VERIFY_CONTEXT,
    signature
);

#[no_mangle]
pub extern "C" fn bls12381_bbs_verify_context_finish(
    handle: u64,
    err: &mut ExternError,
) -> i32 {
    BBS_VERIFY_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<i32, PairingCryptoFfiError> {
            let public_key = get_array_value_from_context!(
                ctx.public_key,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
                "public key"
            );

            let header = if ctx.header.is_empty() {
                None
            } else {
                Some(ctx.header.as_slice())
            };

            let signature = get_array_value_from_context!(
                ctx.signature,
                BBS_BLS12381G1_SIGNATURE_LENGTH,
                "signature"
            );

            let messages = ctx
                .messages
                .iter()
                .map(|m| m.as_ref())
                .collect::<Vec<&[u8]>>();
            let messages = if messages.is_empty() {
                None
            } else {
                Some(messages.as_slice())
            };

            match verify(&BbsVerifyRequest {
                public_key: &public_key,
                header,
                messages,
                signature: &signature,
            })
            .unwrap()
            {
                true => Ok(0),
                false => Ok(1),
            }
        },
    )
}

define_handle_map_deleter!(BBS_VERIFY_CONTEXT, bls12381_bbs_verify_free);
