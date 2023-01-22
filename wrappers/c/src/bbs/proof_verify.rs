use crate::{
    bbs::BbsVerifyProofRequestDto,
    dtos::{ByteArray, PairingCryptoFfiError},
};
use core::convert::TryFrom;
use ffi_support::{ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
        bls12_381_g1_sha_256::proof_verify as bls12_381_sha_256_proof_verify,
        bls12_381_g1_shake_256::proof_verify as bls12_381_shake_256_proof_verify,
    },
    BbsProofVerifyRequest,
};

lazy_static! {
    pub static ref BBS_VERIFY_PROOF_CONTEXT: ConcurrentHandleMap<BbsVerifyProofRequestDto> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(
    BBS_VERIFY_PROOF_CONTEXT,
    bbs_bls12381_verify_proof_free
);

        // $set_total_message_count:ident,
macro_rules! bbs_proof_verify_api_generator {
    (
        $init_wrapper_fn:ident,
        $set_public_key_wrapper_fn:ident,
        $set_header_wrapper_fn:ident,
        $set_proof_fn:ident,
        $set_presentation_header:ident,
        $add_message_wrapper_fn:ident,
        $finish_wrapper_fn:ident,
        $proof_verify_lib_fn:ident
    ) => {
        #[no_mangle]
        pub extern "C" fn $init_wrapper_fn(err: &mut ExternError) -> u64 {
            BBS_VERIFY_PROOF_CONTEXT.insert_with_output(err, || {
                BbsVerifyProofRequestDto {
                    public_key: Vec::new(),
                    header: Vec::new(),
                    proof: Vec::new(),
                    presentation_header: Vec::new(),
                    messages: Vec::new(),
                }
            })
        }

        set_byte_array_impl!(
            $set_public_key_wrapper_fn,
            BBS_VERIFY_PROOF_CONTEXT,
            public_key
        );

        set_byte_array_impl!(
            $set_header_wrapper_fn,
            BBS_VERIFY_PROOF_CONTEXT,
            header
        );

        set_byte_array_impl!($set_proof_fn, BBS_VERIFY_PROOF_CONTEXT, proof);

        set_byte_array_impl!(
            $set_presentation_header,
            BBS_VERIFY_PROOF_CONTEXT,
            presentation_header
        );

        // #[no_mangle]
        // pub extern "C" fn $set_total_message_count(
        //     handle: u64,
        //     value: usize,
        //     err: &mut ExternError,
        // ) -> i32 {
        //     BBS_VERIFY_PROOF_CONTEXT.call_with_output_mut(err, handle, |ctx| {
        //         ctx.total_message_count = value;
        //     });
        //     err.get_code().code()
        // }

        #[no_mangle]
        pub extern "C" fn $add_message_wrapper_fn(
            handle: u64,
            index: usize,
            message: &ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.to_vec();
            if message.is_empty() {
                *err = ExternError::new_error(
                    ErrorCode::new(1),
                    "Message cannot be empty",
                );
                return 1;
            }
            BBS_VERIFY_PROOF_CONTEXT.call_with_output_mut(err, handle, |ctx| {
                ctx.messages.push((index, message));
            });
            err.get_code().code()
        }

        #[no_mangle]
        pub extern "C" fn $finish_wrapper_fn(
            handle: u64,
            err: &mut ExternError,
        ) -> i32 {
            let result = BBS_VERIFY_PROOF_CONTEXT.call_with_result(
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

                    let presentation_header =
                        if ctx.presentation_header.is_empty() {
                            None
                        } else {
                            Some(ctx.presentation_header.as_slice())
                        };

                    let messages = ctx
                        .messages
                        .iter()
                        .map(|(i, m)| (*i, m.as_ref()))
                        .collect::<Vec<(usize, &[u8])>>();

                    let messages = if messages.is_empty() {
                        None
                    } else {
                        Some(messages.as_slice())
                    };

                    if ctx.proof.is_empty() {
                        return Err(PairingCryptoFfiError::new(
                            "proof must be set",
                        ));
                    }

                    match $proof_verify_lib_fn(&BbsProofVerifyRequest {
                        public_key: &public_key,
                        header,
                        proof: &ctx.proof,
                        presentation_header,
                        messages,
                    })? {
                        true => Ok(0),
                        false => Ok(1),
                    }
                },
            );

            if err.get_code().is_success() {
                if result != 0 {
                    *err = ExternError::new_error(
                        ErrorCode::new(1),
                        "verification failed",
                    )
                }
                if let Err(e) = BBS_VERIFY_PROOF_CONTEXT.remove_u64(handle) {
                    *err = ExternError::from(e)
                }
            }

            err.get_code().code()
        }
    };
}

bbs_proof_verify_api_generator!(
    bbs_bls12_381_sha_256_proof_verify_context_init,
    bbs_bls12_381_sha_256_proof_verify_context_set_public_key,
    bbs_bls12_381_sha_256_proof_verify_context_set_header,
    bbs_bls12_381_sha_256_proof_verify_context_set_proof,
    bbs_bls12_381_sha_256_proof_verify_context_set_presentation_header,
    bbs_bls12_381_sha_256_proof_verify_context_add_message,
    bbs_bls12_381_sha_256_proof_verify_context_finish,
    bls12_381_sha_256_proof_verify
);

bbs_proof_verify_api_generator!(
    bbs_bls12_381_shake_256_proof_verify_context_init,
    bbs_bls12_381_shake_256_proof_verify_context_set_public_key,
    bbs_bls12_381_shake_256_proof_verify_context_set_header,
    bbs_bls12_381_shake_256_proof_verify_context_set_proof,
    bbs_bls12_381_shake_256_proof_verify_context_set_presentation_header,
    bbs_bls12_381_shake_256_proof_verify_context_add_message,
    bbs_bls12_381_shake_256_proof_verify_context_finish,
    bls12_381_shake_256_proof_verify
);
