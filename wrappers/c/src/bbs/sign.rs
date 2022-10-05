use crate::{
    bbs::BbsSignRequestDto,
    dtos::{ByteArray, PairingCryptoFfiError},
};
use core::convert::TryFrom;
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::{
            BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
            BBS_BLS12381G1_SECRET_KEY_LENGTH,
        },
        bls12_381_g1_sha_256::sign as bls12_381_sha_256_sign,
        bls12_381_g1_shake_256::sign as bls12_381_shake_256_sign,
    },
    BbsSignRequest,
};

lazy_static! {
    pub static ref BBS_SIGN_CONTEXT: ConcurrentHandleMap<BbsSignRequestDto> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(BBS_SIGN_CONTEXT, bbs_bls12381_sign_free);

macro_rules! bbs_sign_api_generator {
    (
        $init_wrapper_fn:ident,
        $set_secret_key_wrapper_fn:ident,
        $set_public_key_wrapper_fn:ident,
        $set_header_wrapper_fn:ident,
        $add_message_wrapper_fn:ident,
        $finish_wrapper_fn:ident,
        $sign_lib_fn:ident
    ) => {
        #[no_mangle]
        pub extern "C" fn $init_wrapper_fn(err: &mut ExternError) -> u64 {
            BBS_SIGN_CONTEXT.insert_with_output(err, || BbsSignRequestDto {
                secret_key: Vec::new(),
                public_key: Vec::new(),
                header: Vec::new(),
                messages: Vec::new(),
            })
        }

        set_byte_array_impl!(
            $set_secret_key_wrapper_fn,
            BBS_SIGN_CONTEXT,
            secret_key
        );

        set_byte_array_impl!(
            $set_public_key_wrapper_fn,
            BBS_SIGN_CONTEXT,
            public_key
        );

        set_byte_array_impl!($set_header_wrapper_fn, BBS_SIGN_CONTEXT, header);

        add_byte_array_impl!(
            $add_message_wrapper_fn,
            BBS_SIGN_CONTEXT,
            messages
        );

        #[no_mangle]
        pub extern "C" fn $finish_wrapper_fn(
            handle: u64,
            signature: &mut ByteBuffer,
            err: &mut ExternError,
        ) -> i32 {
            let sig = BBS_SIGN_CONTEXT.call_with_result(
                err,
                handle,
                move |ctx| -> Result<ByteBuffer, PairingCryptoFfiError> {
                    let secret_key = get_array_value_from_context!(
                        ctx.secret_key,
                        BBS_BLS12381G1_SECRET_KEY_LENGTH,
                        "secret key"
                    );

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

                    let s = $sign_lib_fn(&BbsSignRequest {
                        secret_key: &secret_key,
                        public_key: &public_key,
                        header,
                        messages,
                    })?;
                    Ok(ByteBuffer::from_vec(s.to_vec()))
                },
            );

            if err.get_code().is_success() {
                *signature = sig;
                if let Err(e) = BBS_SIGN_CONTEXT.remove_u64(handle) {
                    *err = ExternError::new_error(
                        ErrorCode::new(1),
                        format!("{:?}", e),
                    )
                }
            }
            err.get_code().code()
        }
    };
}

bbs_sign_api_generator!(
    bbs_bls12_381_sha_256_sign_context_init,
    bbs_bls12_381_sha_256_sign_context_set_secret_key,
    bbs_bls12_381_sha_256_sign_context_set_public_key,
    bbs_bls12_381_sha_256_sign_context_set_header,
    bbs_bls12_381_sha_256_sign_context_add_message,
    bbs_bls12_381_sha_256_sign_context_finish,
    bls12_381_sha_256_sign
);

bbs_sign_api_generator!(
    bbs_bls12_381_shake_256_sign_context_init,
    bbs_bls12_381_shake_256_sign_context_set_secret_key,
    bbs_bls12_381_shake_256_sign_context_set_public_key,
    bbs_bls12_381_shake_256_sign_context_set_header,
    bbs_bls12_381_shake_256_sign_context_add_message,
    bbs_bls12_381_shake_256_sign_context_finish,
    bls12_381_shake_256_sign
);
