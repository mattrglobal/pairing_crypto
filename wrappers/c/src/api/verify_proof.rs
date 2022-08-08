use crate::dtos::{BbsVerifyProofRequestDto, ByteArray, PairingCryptoFfiError};
use core::convert::TryFrom;
use ffi_support::{ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs::ciphersuites::bls12_381::{
    proof_verify,
    BbsProofVerifyRequest,
    BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
};

lazy_static! {
    pub static ref BBS_VERIFY_PROOF_CONTEXT: ConcurrentHandleMap<BbsVerifyProofRequestDto> =
        ConcurrentHandleMap::new();
}

#[no_mangle]
pub extern "C" fn bbs_bls12381_verify_proof_context_init(
    err: &mut ExternError,
) -> u64 {
    BBS_VERIFY_PROOF_CONTEXT.insert_with_output(err, || {
        BbsVerifyProofRequestDto {
            public_key: Vec::new(),
            header: Vec::new(),
            proof: Vec::new(),
            presentation_message: Vec::new(),
            messages: Vec::new(),
            total_message_count: 0,
        }
    })
}

set_byte_array_impl!(
    bbs_bls12381_verify_proof_context_set_public_key,
    BBS_VERIFY_PROOF_CONTEXT,
    public_key
);

set_byte_array_impl!(
    bbs_bls12381_verify_proof_context_set_header,
    BBS_VERIFY_PROOF_CONTEXT,
    header
);

set_byte_array_impl!(
    bbs_bls12381_verify_proof_context_set_proof,
    BBS_VERIFY_PROOF_CONTEXT,
    proof
);

set_byte_array_impl!(
    bbs_bls12381_verify_proof_context_set_presentation_message,
    BBS_VERIFY_PROOF_CONTEXT,
    presentation_message
);

#[no_mangle]
pub extern "C" fn bbs_bls12381_verify_proof_context_set_total_message_count(
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
pub extern "C" fn bbs_bls12381_verify_proof_context_add_message(
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
pub extern "C" fn bbs_bls12381_verify_proof_context_finish(
    handle: u64,
    err: &mut ExternError,
) -> i32 {
    BBS_VERIFY_PROOF_CONTEXT.call_with_result(
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

            let presentation_message = if ctx.presentation_message.is_empty() {
                None
            } else {
                Some(ctx.presentation_message.as_slice())
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
                return Err(PairingCryptoFfiError::new("proof must be set"));
            }

            match proof_verify(&BbsProofVerifyRequest {
                public_key: &public_key,
                header,
                proof: &ctx.proof,
                presentation_message,
                messages,
                total_message_count: ctx.total_message_count,
            })? {
                true => Ok(0),
                false => Ok(1),
            }
        },
    )
}

define_handle_map_deleter!(
    BBS_VERIFY_PROOF_CONTEXT,
    bbs_bls12381_verify_proof_free
);
