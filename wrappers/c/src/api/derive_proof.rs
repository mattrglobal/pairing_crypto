use crate::dtos::{
    BbsDeriveProofRequestDto,
    BbsDeriveProofRevealMessageRequestDto,
    ByteArray,
    PairingCryptoFfiError,
};
use core::convert::TryFrom;
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::{
            BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
            BBS_BLS12381G1_SIGNATURE_LENGTH,
        },
        bls12_381_shake_256::proof_gen as bls12_381_shake_256_proof_gen,
    },
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
};

lazy_static! {
    pub static ref BBS_DERIVE_PROOF_CONTEXT: ConcurrentHandleMap<BbsDeriveProofRequestDto> =
        ConcurrentHandleMap::new();
}

#[no_mangle]
pub extern "C" fn bbs_bls12381_derive_proof_context_init(
    err: &mut ExternError,
) -> u64 {
    BBS_DERIVE_PROOF_CONTEXT.insert_with_output(err, || {
        BbsDeriveProofRequestDto {
            public_key: Vec::new(),
            header: Vec::new(),
            messages: Vec::new(),
            signature: Vec::new(),
            presentation_message: Vec::new(),
        }
    })
}

set_byte_array_impl!(
    bbs_bls12381_derive_proof_context_set_public_key,
    BBS_DERIVE_PROOF_CONTEXT,
    public_key
);

set_byte_array_impl!(
    bbs_bls12381_derive_proof_context_set_header,
    BBS_DERIVE_PROOF_CONTEXT,
    header
);

set_byte_array_impl!(
    bbs_bls12381_derive_proof_context_set_signature,
    BBS_DERIVE_PROOF_CONTEXT,
    signature
);

set_byte_array_impl!(
    bbs_bls12381_derive_proof_context_set_presentation_message,
    BBS_DERIVE_PROOF_CONTEXT,
    presentation_message
);

#[no_mangle]
pub extern "C" fn bbs_bls12381_derive_proof_context_add_message(
    handle: u64,
    reveal: bool,
    message: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let message = message.to_vec();
    if message.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "empty message");
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
pub extern "C" fn bbs_bls12381_derive_proof_context_finish(
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

            let presentation_message = if ctx.presentation_message.is_empty() {
                None
            } else {
                Some(ctx.presentation_message.as_slice())
            };

            let proof = bls12_381_shake_256_proof_gen(&BbsProofGenRequest {
                public_key: &public_key,
                header,
                messages,
                signature: &signature,
                presentation_message,
            })?;

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

define_handle_map_deleter!(
    BBS_DERIVE_PROOF_CONTEXT,
    bbs_bls12381_derive_proof_free
);
