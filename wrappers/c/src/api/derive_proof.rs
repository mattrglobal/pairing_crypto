use crate::dtos::{
    BbsDeriveProofRequestDto, BbsDeriveProofRevealMessageRequestDto, ByteArray,
    PairingCryptoFfiError,
};
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bls12_381::bbs::*;

lazy_static! {
    pub static ref BBS_DERIVE_PROOF_CONTEXT: ConcurrentHandleMap<BbsDeriveProofRequestDto> =
        ConcurrentHandleMap::new();
}

#[no_mangle]
pub extern "C" fn bls12381_bbs_derive_proof_context_init(err: &mut ExternError) -> u64 {
    BBS_DERIVE_PROOF_CONTEXT.insert_with_output(err, || BbsDeriveProofRequestDto {
        public_key: Vec::new(),
        messages: Vec::new(),
        signature: Vec::new(),
        presentation_message: Vec::new(),
    })
}

set_byte_array_impl!(
    bls12381_bbs_derive_proof_context_set_public_key,
    BBS_DERIVE_PROOF_CONTEXT,
    public_key
);

set_byte_array_impl!(
    bls12381_bbs_derive_proof_context_set_signature,
    BBS_DERIVE_PROOF_CONTEXT,
    signature
);

set_byte_array_impl!(
    bls12381_bbs_derive_proof_context_set_presentation_message,
    BBS_DERIVE_PROOF_CONTEXT,
    presentation_message
);

#[no_mangle]
pub extern "C" fn bls12381_bbs_derive_proof_context_add_message(
    handle: u64,
    message: &mut ByteArray,
    reveal: bool,
    err: &mut ExternError,
) -> i32 {
    let message = message.to_vec();
    if message.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
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
pub extern "C" fn bls12381_bbs_derive_proof_context_finish(
    handle: u64,
    proof: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let result = BBS_DERIVE_PROOF_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<ByteBuffer, PairingCryptoFfiError> {
            if ctx.public_key.is_empty() {
                return Err(PairingCryptoFfiError::new("public_key must be set"));
            }
            if ctx.messages.is_empty() {
                return Err(PairingCryptoFfiError::new("messages cannot be empty"));
            }
            if ctx.signature.is_empty() {
                return Err(PairingCryptoFfiError::new("signature must be set"));
            }
            if ctx.presentation_message.is_empty() {
                return Err(PairingCryptoFfiError::new(
                    "presentation_message must be set",
                ));
            }

            let proof = derive_proof(BbsDeriveProofRequest {
                public_key: ctx.public_key.clone(),
                signature: ctx.signature.clone(),
                presentation_message: ctx.presentation_message.clone(),
                messages: ctx
                    .messages
                    .iter()
                    .map(|item| BbsDeriveProofRevealMessageRequest {
                        reveal: item.reveal,
                        value: item.value.clone(),
                    })
                    .collect(),
            })
            .unwrap(); // TODO dont un-wrap here

            Ok(ByteBuffer::from_vec(proof.to_vec()))
        },
    );

    if err.get_code().is_success() {
        *proof = result;
        if let Err(e) = BBS_DERIVE_PROOF_CONTEXT.remove_u64(handle) {
            *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e))
        }
    }
    err.get_code().code()
}

define_handle_map_deleter!(BBS_DERIVE_PROOF_CONTEXT, bls12381_bbs_derive_proof_free);
