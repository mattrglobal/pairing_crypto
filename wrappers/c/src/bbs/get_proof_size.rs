use std::convert::TryInto;

use pairing_crypto::bbs::ciphersuites::bls12_381::get_proof_size;

macro_rules! bbs_get_proof_size_api_generator {
    (
        $get_proof_size_wrapper_fn:ident,
        $get_proof_size_lib_fn:ident
    ) => {
        /// Return the size of proof in bytes.
        ///
        /// * num_undisclosed_messages: number of undisclosed messages from
        ///   orginal message set
        #[no_mangle]
        pub extern "C" fn $get_proof_size_wrapper_fn(
            num_undisclosed_messages: usize,
        ) -> i32 {
            if let Ok(s) =
                $get_proof_size_lib_fn(num_undisclosed_messages).try_into()
            {
                return s;
            }
            return -1;
        }
    };
}

bbs_get_proof_size_api_generator!(
    bbs_bls12_381_sha_256_get_proof_size,
    get_proof_size
);

bbs_get_proof_size_api_generator!(
    bbs_bls12_381_shake_256_get_proof_size,
    get_proof_size
);
