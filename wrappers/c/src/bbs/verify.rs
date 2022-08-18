use crate::{
    bbs::BbsVerifyRequestDto,
    dtos::{ByteArray, PairingCryptoFfiError},
};
use core::convert::TryFrom;
use ffi_support::{ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::{
            BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
            BBS_BLS12381G1_SIGNATURE_LENGTH,
        },
        bls12_381_sha_256::verify as bls12_381_sha_256_verify,
        bls12_381_shake_256::verify as bls12_381_shake_256_verify,
    },
    BbsVerifyRequest,
};

lazy_static! {
    pub static ref BBS_VERIFY_CONTEXT: ConcurrentHandleMap<BbsVerifyRequestDto> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(BBS_VERIFY_CONTEXT, bbs_bls12381_verify_free);

macro_rules! bbs_verify_api_generator {
    (
        $init_wrapper_fn:ident,
        $set_public_key_wrapper_fn:ident,
        $set_header_wrapper_fn:ident,
        $add_message_wrapper_fn:ident,
        $set_signature_wrapper_fn:ident,
        $finish_wrapper_fn:ident,
        $verify_lib_fn:ident
    ) => {
        #[no_mangle]
        pub extern "C" fn $init_wrapper_fn(err: &mut ExternError) -> u64 {
            BBS_VERIFY_CONTEXT.insert_with_output(err, || BbsVerifyRequestDto {
                public_key: Vec::new(),
                header: Vec::new(),
                messages: Vec::new(),
                signature: Vec::new(),
            })
        }

        set_byte_array_impl!(
            $set_public_key_wrapper_fn,
            BBS_VERIFY_CONTEXT,
            public_key
        );

        set_byte_array_impl!(
            $set_header_wrapper_fn,
            BBS_VERIFY_CONTEXT,
            header
        );

        add_byte_array_impl!(
            $add_message_wrapper_fn,
            BBS_VERIFY_CONTEXT,
            messages
        );

        set_byte_array_impl!(
            $set_signature_wrapper_fn,
            BBS_VERIFY_CONTEXT,
            signature
        );

        #[no_mangle]
        pub extern "C" fn $finish_wrapper_fn(
            handle: u64,
            err: &mut ExternError,
        ) -> i32 {
            let _ = BBS_VERIFY_CONTEXT.call_with_result(
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

                    match $verify_lib_fn(&BbsVerifyRequest {
                        public_key: &public_key,
                        header,
                        messages,
                        signature: &signature,
                    })? {
                        true => Ok(0),
                        false => Ok(1),
                    }
                },
            );
            if err.get_code().is_success() {
                if let Err(e) = BBS_VERIFY_CONTEXT.remove_u64(handle) {
                    *err = ExternError::from(e)
                }
            }

            err.get_code().code()
        }
    };
}

bbs_verify_api_generator!(
    bbs_bls12_381_sha_256_verify_context_init,
    bbs_bls12_381_sha_256_verify_context_set_public_key,
    bbs_bls12_381_sha_256_verify_context_set_header,
    bbs_bls12_381_sha_256_verify_context_add_message,
    bbs_bls12_381_sha_256_verify_context_set_signature,
    bbs_bls12_381_sha_256_verify_context_finish,
    bls12_381_sha_256_verify
);

bbs_verify_api_generator!(
    bbs_bls12_381_shake_256_verify_context_init,
    bbs_bls12_381_shake_256_verify_context_set_public_key,
    bbs_bls12_381_shake_256_verify_context_set_header,
    bbs_bls12_381_shake_256_verify_context_add_message,
    bbs_bls12_381_shake_256_verify_context_set_signature,
    bbs_bls12_381_shake_256_verify_context_finish,
    bls12_381_shake_256_verify
);
