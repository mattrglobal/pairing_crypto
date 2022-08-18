use ffi_support::ExternError;
use jni::{
    objects::JObject,
    sys::{jbyteArray, jint, jlong},
    JNIEnv,
};

use crate::update_last_error;
use pairing_crypto_c::{
    bbs::{
        proof_verify::{
            bbs_bls12_381_sha_256_proof_verify_context_add_message,
            bbs_bls12_381_sha_256_proof_verify_context_finish,
            bbs_bls12_381_sha_256_proof_verify_context_init,
            bbs_bls12_381_sha_256_proof_verify_context_set_header,
            bbs_bls12_381_sha_256_proof_verify_context_set_presentation_message,
            bbs_bls12_381_sha_256_proof_verify_context_set_proof,
            bbs_bls12_381_sha_256_proof_verify_context_set_public_key,
            bbs_bls12_381_sha_256_proof_verify_context_set_total_message_count,
            bbs_bls12_381_shake_256_proof_verify_context_add_message,
            bbs_bls12_381_shake_256_proof_verify_context_finish,
            bbs_bls12_381_shake_256_proof_verify_context_init,
            bbs_bls12_381_shake_256_proof_verify_context_set_header,
            bbs_bls12_381_shake_256_proof_verify_context_set_presentation_message,
            bbs_bls12_381_shake_256_proof_verify_context_set_proof,
            bbs_bls12_381_shake_256_proof_verify_context_set_public_key,
            bbs_bls12_381_shake_256_proof_verify_context_set_total_message_count,
        },
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
    },
    dtos::ByteArray,
};

macro_rules! bbs_proof_gen_api_wrapper_generator {
    (
        $java_wrapper_init_fn:ident,
        $init_fn:ident,
        $java_wrapper_set_public_key_fn:ident,
        $set_public_key_fn:ident,
        $java_wrapper_set_header_fn:ident,
        $set_header_fn:ident,
        $java_wrapper_set_proof_fn:ident,
        $set_proof_fn:ident,
        $java_wrapper_set_presentation_message_fn:ident,
        $set_presentation_message_fn:ident,
        $java_wrapper_set_total_message_count_fn:ident,
        $set_total_message_count_fn:ident,
        $java_wrapper_add_message_fn:ident,
        $add_message_fn:ident,
        $java_wrapper_finish_fn:ident,
        $finish_fn:ident
    ) => {
        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_init_fn(
            _: JNIEnv,
            _: JObject,
        ) -> jlong {
            let mut error = ExternError::success();
            $init_fn(&mut error) as jlong
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_set_public_key_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            public_key: jbyteArray,
        ) -> jint {
            match env.convert_byte_array(public_key) {
                Err(_) => 1,
                Ok(s) => {
                    if s.len() != BBS_BLS12381G1_PUBLIC_KEY_LENGTH {
                        2
                    } else {
                        let mut error = ExternError::success();
                        let byte_array = ByteArray::from(&s);
                        $set_public_key_fn(
                            handle as u64,
                            &byte_array,
                            &mut error,
                        )
                    }
                }
            }
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_set_header_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            header: jbyteArray,
        ) -> jint {
            match env.convert_byte_array(header) {
                Err(_) => 1,
                Ok(s) => {
                    let mut error = ExternError::success();
                    let byte_array = ByteArray::from(&s);
                    $set_header_fn(handle as u64, &byte_array, &mut error)
                }
            }
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_set_proof_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            proof: jbyteArray,
        ) -> jint {
            match env.convert_byte_array(proof) {
                Err(_) => 1,
                Ok(s) => {
                    let mut error = ExternError::success();
                    let byte_array = ByteArray::from(&s);
                    let res =
                        $set_proof_fn(handle as u64, &byte_array, &mut error);
                    if res != 0 {
                        update_last_error(error.get_message().as_str());
                    }
                    res
                }
            }
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_set_presentation_message_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            presentation_message: jbyteArray,
        ) -> jint {
            match env.convert_byte_array(presentation_message) {
                Err(_) => 1,
                Ok(s) => {
                    let mut error = ExternError::success();
                    let byte_array = ByteArray::from(&s);
                    $set_presentation_message_fn(
                        handle as u64,
                        &byte_array,
                        &mut error,
                    )
                }
            }
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_set_total_message_count_fn(
            _: JNIEnv,
            _: JObject,
            handle: jlong,
            total_message_count: jint,
        ) -> jint {
            match usize::try_from(total_message_count) {
                Err(_) => 1,
                Ok(c) => {
                    let mut error = ExternError::success();
                    $set_total_message_count_fn(handle as u64, c, &mut error)
                }
            }
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_add_message_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            index: jint,
            message: jbyteArray,
        ) -> jint {
            match env.convert_byte_array(message) {
                Err(_) => 1,
                Ok(s) => {
                    let mut error = ExternError::success();
                    let byte_array = ByteArray::from(&s);
                    match usize::try_from(index) {
                        Err(_) => 1,
                        Ok(i) => $add_message_fn(
                            handle as u64,
                            i,
                            &byte_array,
                            &mut error,
                        ),
                    }
                }
            }
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_finish_fn(
            _: JNIEnv,
            _: JObject,
            handle: jlong,
        ) -> jint {
            let mut error = ExternError::success();
            $finish_fn(handle as u64, &mut error)
        }
    };
}

bbs_proof_gen_api_wrapper_generator!(
    Java_pairing_1crypto_Bls12381Sha256_proof_1verify_1context_1init,
    bbs_bls12_381_sha_256_proof_verify_context_init,
    Java_pairing_1crypto_Bls12381Sha256_proof_1verify_1context_1set_1public_1key,
    bbs_bls12_381_sha_256_proof_verify_context_set_public_key,
    Java_pairing_1crypto_Bls12381Sha256_proof_1verify_1context_1set_1header,
    bbs_bls12_381_sha_256_proof_verify_context_set_header,
    Java_pairing_1crypto_Bls12381Sha256_proof_1verify_1context_1set_1proof,
    bbs_bls12_381_sha_256_proof_verify_context_set_proof,
    Java_pairing_1crypto_Bls12381Sha256_proof_1verify_1context_1set_1presentation_1message,
    bbs_bls12_381_sha_256_proof_verify_context_set_presentation_message,
    Java_pairing_1crypto_Bls12381Sha256_proof_1verify_1context_1set_1total_1message_1count,
    bbs_bls12_381_sha_256_proof_verify_context_set_total_message_count,
    Java_pairing_1crypto_Bls12381Sha256_proof_1verify_1context_1add_1message,
    bbs_bls12_381_sha_256_proof_verify_context_add_message,
    Java_pairing_1crypto_Bls12381Sha256_proof_1verify_1context_1finish,
    bbs_bls12_381_sha_256_proof_verify_context_finish
);

bbs_proof_gen_api_wrapper_generator!(
    Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1init,
    bbs_bls12_381_shake_256_proof_verify_context_init,
    Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1set_1public_1key,
    bbs_bls12_381_shake_256_proof_verify_context_set_public_key,
    Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1set_1header,
    bbs_bls12_381_shake_256_proof_verify_context_set_header,
    Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1set_1proof,
    bbs_bls12_381_shake_256_proof_verify_context_set_proof,
    Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1set_1presentation_1message,
    bbs_bls12_381_shake_256_proof_verify_context_set_presentation_message,
    Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1set_1total_1message_1count,
    bbs_bls12_381_shake_256_proof_verify_context_set_total_message_count,
    Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1add_1message,
    bbs_bls12_381_shake_256_proof_verify_context_add_message,
    Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1finish,
    bbs_bls12_381_shake_256_proof_verify_context_finish
);
