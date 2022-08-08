use std::convert::TryInto;

use pairing_crypto::bbs::ciphersuites::bls12_381::get_proof_size;

/// Return the size of proof in bytes.
///
/// * num_undisclosed_messages: number of undisclosed messages from orginal
///   message set
#[no_mangle]
pub extern "C" fn bbs_bls12381_get_proof_size(
    num_undisclosed_messages: usize,
) -> i32 {
    if let Ok(s) = get_proof_size(num_undisclosed_messages).try_into() {
        return s;
    }
    return -1;
}
