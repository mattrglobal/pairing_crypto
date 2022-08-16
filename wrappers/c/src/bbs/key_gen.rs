use crate::dtos::ByteArray;
use ffi_support::{ByteBuffer, ErrorCode, ExternError};
use pairing_crypto::bbs::ciphersuites::bls12_381::KeyPair;

macro_rules! bbs_key_gen_api_generator {
    (
        $generate_key_pair_wrapper_fn:ident
    ) => {
        /// Generate a BBS BLS 12-381 curve key pair in the field.
        ///
        /// * ikm: UInt8Array with 32 elements
        /// * key_info: UInt8Array with 32 elements
        #[no_mangle]
        pub extern "C" fn $generate_key_pair_wrapper_fn(
            ikm: ByteArray,
            key_info: ByteArray,
            secret_key: &mut ByteBuffer,
            public_key: &mut ByteBuffer,
            err: &mut ExternError,
        ) -> i32 {
            // Derive secret key from supplied IKM and key information metadata.
            if let Some(key_pair) = KeyPair::new(
                ikm.to_vec(),
                key_info.to_opt_vec().as_ref().map(Vec::as_ref),
            ) {
                *secret_key = ByteBuffer::from_vec(
                    key_pair.secret_key.to_bytes().to_vec(),
                );
                *public_key = ByteBuffer::from_vec(
                    key_pair.public_key.to_octets().to_vec(),
                );
                *err = ExternError::success();
                return 0;
            }
            *err = ExternError::new_error(
                ErrorCode::new(1),
                "unexpected failure".to_owned(),
            );
            return 1;
        }
    };
}

bbs_key_gen_api_generator!(bbs_bls12_381_sha_256_generate_key_pair);
bbs_key_gen_api_generator!(bbs_bls12_381_shake_256_generate_key_pair);
