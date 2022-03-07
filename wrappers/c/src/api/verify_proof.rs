use crate::dtos::{BbsVerifyProofRequestDto, ByteArray, PairingCryptoFfiError};
use ffi_support::{ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bls12_381::bbs::*;

lazy_static! {
    pub static ref BBS_VERIFY_PROOF_CONTEXT: ConcurrentHandleMap<BbsVerifyProofRequestDto> =
        ConcurrentHandleMap::new();
}

#[no_mangle]
pub extern "C" fn bls12381_bbs_verify_proof_context_init(err: &mut ExternError) -> u64 {
    BBS_VERIFY_PROOF_CONTEXT.insert_with_output(err, || BbsVerifyProofRequestDto {
        public_key: Vec::new(),
        messages: Vec::new(),
        proof: Vec::new(),
        presentation_message: Vec::new(),
        total_message_count: 0,
    })
}

set_byte_array_impl!(
    bls12381_bbs_verify_proof_context_set_public_key,
    BBS_VERIFY_PROOF_CONTEXT,
    public_key
);

set_byte_array_impl!(
    bls12381_bbs_verify_proof_context_set_proof,
    BBS_VERIFY_PROOF_CONTEXT,
    proof
);

set_byte_array_impl!(
    bls12381_bbs_verify_proof_context_set_presentation_message,
    BBS_VERIFY_PROOF_CONTEXT,
    presentation_message
);

#[no_mangle]
pub extern "C" fn bls12381_bbs_verify_proof_context_set_total_message_count(
    handle: u64,
    value: usize,
    err: &mut ExternError,
) -> i32 {
    BBS_VERIFY_PROOF_CONTEXT.call_with_output_mut(err, handle, |ctx| {
        ctx.total_message_count = value;
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bls12381_bbs_verify_proof_context_add_message(
    handle: u64,
    message: &mut ByteArray,
    index: usize,
    err: &mut ExternError,
) -> i32 {
    let message = message.to_vec();
    if message.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
        return 1;
    }
    BBS_VERIFY_PROOF_CONTEXT.call_with_output_mut(err, handle, |ctx| {
        ctx.messages.push((index, message));
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bls12381_bbs_verify_proof_context_finish(
    handle: u64,
    err: &mut ExternError,
) -> i32 {
    BBS_VERIFY_PROOF_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<i32, PairingCryptoFfiError> {
            if ctx.public_key.is_empty() {
                return Err(PairingCryptoFfiError::new("public_key must be set"));
            }
            if ctx.messages.is_empty() {
                return Err(PairingCryptoFfiError::new("messages cannot be empty"));
            }
            if ctx.proof.is_empty() {
                return Err(PairingCryptoFfiError::new("proof must be set"));
            }
            if ctx.presentation_message.is_empty() {
                return Err(PairingCryptoFfiError::new(
                    "presentation_message must be set",
                ));
            }
            if ctx.total_message_count == 0 {
                return Err(PairingCryptoFfiError::new(
                    "total_message_count must be set and greater than 0",
                ));
            }

            match verify_proof(BbsVerifyProofRequest {
                public_key: ctx.public_key.clone(),
                messages: ctx.messages.clone(),
                proof: ctx.proof.clone(),
                presentation_message: ctx.presentation_message.clone(),
                total_message_count: ctx.total_message_count,
            })
            .unwrap()
            {
                true => Ok(0),
                false => Ok(1),
            }
        },
    )
}

define_handle_map_deleter!(BBS_VERIFY_PROOF_CONTEXT, bls12381_bbs_verify_proof_free);
