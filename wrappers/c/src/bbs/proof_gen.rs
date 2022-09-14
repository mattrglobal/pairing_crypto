use crate::{
    bbs::{BbsDeriveProofRequestDto, BbsDeriveProofRevealMessageRequestDto},
    dtos::{ByteArray, PairingCryptoFfiError},
};
use core::convert::TryFrom;
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::{
            BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
            BBS_BLS12381G1_SIGNATURE_LENGTH,
        },
        bls12_381_g1_sha_256::proof_gen as bls12_381_sha_256_proof_gen,
        bls12_381_g1_shake_256::proof_gen as bls12_381_shake_256_proof_gen,
    },
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
};

lazy_static! {
    pub static ref BBS_DERIVE_PROOF_CONTEXT: ConcurrentHandleMap<BbsDeriveProofRequestDto> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(
    BBS_DERIVE_PROOF_CONTEXT,
    bbs_bls12381_derive_proof_free
);

macro_rules! bbs_proof_gen_api_generator {
    (
        $init_wrapper_fn:ident,
        $set_public_key_wrapper_fn:ident,
        $set_header_wrapper_fn:ident,
        $set_signature_fn:ident,
        $set_presentation_header:ident,
        $set_verify_signature: ident,
        $add_message_wrapper_fn:ident,
        $finish_wrapper_fn:ident,
        $proof_gen_lib_fn:ident
    ) => {
        #[no_mangle]
        pub extern "C" fn $init_wrapper_fn(err: &mut ExternError) -> u64 {
            BBS_DERIVE_PROOF_CONTEXT.insert_with_output(err, || {
                BbsDeriveProofRequestDto {
                    public_key: Vec::new(),
                    header: Vec::new(),
                    messages: Vec::new(),
                    signature: Vec::new(),
                    presentation_header: Vec::new(),
                    verify_signature: None,
                }
            })
        }

        set_byte_array_impl!(
            $set_public_key_wrapper_fn,
            BBS_DERIVE_PROOF_CONTEXT,
            public_key
        );

        set_byte_array_impl!(
            $set_header_wrapper_fn,
            BBS_DERIVE_PROOF_CONTEXT,
            header
        );

        set_byte_array_impl!(
            $set_signature_fn,
            BBS_DERIVE_PROOF_CONTEXT,
            signature
        );

        set_byte_array_impl!(
            $set_presentation_header,
            BBS_DERIVE_PROOF_CONTEXT,
            presentation_header
        );

        #[no_mangle]
        pub extern "C" fn $add_message_wrapper_fn(
            handle: u64,
            reveal: bool,
            message: &ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.to_vec();
            if message.is_empty() {
                *err =
                    ExternError::new_error(ErrorCode::new(1), "empty message");
                return 1;
            }
            BBS_DERIVE_PROOF_CONTEXT.call_with_output_mut(err, handle, |ctx| {
                ctx.messages.push(BbsDeriveProofRevealMessageRequestDto {
                    value: message,
                    reveal,
                });
            });
            err.get_code().code()
        }

        #[no_mangle]
        pub extern "C" fn $set_verify_signature(
            handle: u64,
            verify_signature: bool,
            err: &mut ExternError,
        ) -> i32 {
            BBS_DERIVE_PROOF_CONTEXT.call_with_output_mut(err, handle, |ctx| {
                ctx.verify_signature = Some(verify_signature);
            });
            err.get_code().code()
        }

        #[no_mangle]
        pub extern "C" fn $finish_wrapper_fn(
            handle: u64,
            proof: &mut ByteBuffer,
            err: &mut ExternError,
        ) -> i32 {
            let result = BBS_DERIVE_PROOF_CONTEXT.call_with_result(
                err,
                handle,
                move |ctx| -> Result<ByteBuffer, PairingCryptoFfiError> {
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
                        .map(|item| BbsProofGenRevealMessageRequest {
                            reveal: item.reveal,
                            value: item.value.as_ref(),
                        })
                        .collect::<Vec<BbsProofGenRevealMessageRequest<_>>>();
                    let messages = if messages.is_empty() {
                        None
                    } else {
                        Some(messages.as_slice())
                    };

                    let presentation_header =
                        if ctx.presentation_header.is_empty() {
                            None
                        } else {
                            Some(ctx.presentation_header.as_slice())
                        };

                    let proof = $proof_gen_lib_fn(&BbsProofGenRequest {
                        public_key: &public_key,
                        header,
                        messages,
                        signature: &signature,
                        presentation_header,
                        verify_signature: ctx.verify_signature,
                    })?;

                    Ok(ByteBuffer::from_vec(proof.to_vec()))
                },
            );

            if err.get_code().is_success() {
                *proof = result;
                if let Err(e) = BBS_DERIVE_PROOF_CONTEXT.remove_u64(handle) {
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

bbs_proof_gen_api_generator!(
    bbs_bls12_381_sha_256_proof_gen_context_init,
    bbs_bls12_381_sha_256_proof_gen_context_set_public_key,
    bbs_bls12_381_sha_256_proof_gen_context_set_header,
    bbs_bls12_381_sha_256_proof_gen_context_set_signature,
    bbs_bls12_381_sha_256_proof_gen_context_set_presentation_header,
    bbs_bls12_381_sha_256_proof_gen_context_set_verify_signature,
    bbs_bls12_381_sha_256_proof_gen_context_add_message,
    bbs_bls12_381_sha_256_proof_gen_context_finish,
    bls12_381_sha_256_proof_gen
);

bbs_proof_gen_api_generator!(
    bbs_bls12_381_shake_256_proof_gen_context_init,
    bbs_bls12_381_shake_256_proof_gen_context_set_public_key,
    bbs_bls12_381_shake_256_proof_gen_context_set_header,
    bbs_bls12_381_shake_256_proof_gen_context_set_signature,
    bbs_bls12_381_shake_256_proof_gen_context_set_presentation_header,
    bbs_bls12_381_shake_256_proof_gen_context_set_verify_signature,
    bbs_bls12_381_shake_256_proof_gen_context_add_message,
    bbs_bls12_381_shake_256_proof_gen_context_finish,
    bls12_381_shake_256_proof_gen
);
