use ffi_support::{ByteBuffer, ExternError};
use jni::{
    objects::JObject,
    sys::{jboolean, jbyte, jbyteArray, jint, jlong},
    JNIEnv,
};

use crate::update_last_error;
use pairing_crypto_c::{
    bbs::{
        proof_gen::{
            bbs_bls12_381_sha_256_proof_gen_context_add_message,
            bbs_bls12_381_sha_256_proof_gen_context_finish,
            bbs_bls12_381_sha_256_proof_gen_context_init,
            bbs_bls12_381_sha_256_proof_gen_context_set_header,
            bbs_bls12_381_sha_256_proof_gen_context_set_presentation_header,
            bbs_bls12_381_sha_256_proof_gen_context_set_public_key,
            bbs_bls12_381_sha_256_proof_gen_context_set_signature,
            bbs_bls12_381_sha_256_proof_gen_context_set_verify_signature,
            bbs_bls12_381_shake_256_proof_gen_context_add_message,
            bbs_bls12_381_shake_256_proof_gen_context_finish,
            bbs_bls12_381_shake_256_proof_gen_context_init,
            bbs_bls12_381_shake_256_proof_gen_context_set_header,
            bbs_bls12_381_shake_256_proof_gen_context_set_presentation_header,
            bbs_bls12_381_shake_256_proof_gen_context_set_public_key,
            bbs_bls12_381_shake_256_proof_gen_context_set_signature,
            bbs_bls12_381_shake_256_proof_gen_context_set_verify_signature,
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
        $java_wrapper_set_signature_fn:ident,
        $set_signature_fn:ident,
        $java_wrapper_set_presentation_header_fn:ident,
        $set_presentation_header_fn:ident,
        $java_wrapper_set_verify_signature_fn:ident,
        $set_verify_signature_fn:ident,
        $java_wrapper_add_message_fn:ident,
        $add_message_fn:ident,
        $java_wrapper_finish_fn:ident,
        $finish_fn:ident,
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
        pub extern "C" fn $java_wrapper_set_signature_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            signature: jbyteArray,
        ) -> jint {
            match env.convert_byte_array(signature) {
                Err(_) => 1,
                Ok(s) => {
                    let mut error = ExternError::success();
                    let byte_array = ByteArray::from(&s);
                    let res = $set_signature_fn(
                        handle as u64,
                        &byte_array,
                        &mut error,
                    );
                    if res != 0 {
                        update_last_error(error.get_message().as_str());
                    }
                    res
                }
            }
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_set_presentation_header_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            presentation_header: jbyteArray,
        ) -> jint {
            match env.convert_byte_array(presentation_header) {
                Err(_) => 1,
                Ok(s) => {
                    let mut error = ExternError::success();
                    let byte_array = ByteArray::from(&s);
                    $set_presentation_header_fn(
                        handle as u64,
                        &byte_array,
                        &mut error,
                    )
                }
            }
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_set_verify_signature_fn(
            _: JNIEnv,
            _: JObject,
            handle: jlong,
            verify_signature: jboolean,
        ) -> jint {
            let mut error = ExternError::success();
            $set_verify_signature_fn(
                handle as u64,
                verify_signature != 0,
                &mut error,
            )
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_add_message_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            reveal: jboolean,
            message: jbyteArray,
        ) -> jint {
            match env.convert_byte_array(message) {
                Err(_) => 1,
                Ok(s) => {
                    let mut error = ExternError::success();
                    let byte_array = ByteArray::from(&s);
                    $add_message_fn(
                        handle as u64,
                        reveal != 0,
                        &byte_array,
                        &mut error,
                    )
                }
            }
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_finish_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            proof: jbyteArray,
        ) -> jint {
            let mut error = ExternError::success();
            let mut p = ByteBuffer::from_vec(vec![]);
            let res = $finish_fn(handle as u64, &mut p, &mut error);
            if res != 0 {
                return res;
            }
            let res = p.destroy_into_vec();
            let pp: Vec<jbyte> = res.iter().map(|b| *b as jbyte).collect();
            copy_to_jni!(env, proof, pp.as_slice());
            0
        }
    };
}

bbs_proof_gen_api_wrapper_generator!(
    Java_pairing_1crypto_Bls12381Sha256_proof_1gen_1context_1init,
    bbs_bls12_381_sha_256_proof_gen_context_init,
    Java_pairing_1crypto_Bls12381Sha256_proof_1gen_1context_1set_1public_1key,
    bbs_bls12_381_sha_256_proof_gen_context_set_public_key,
    Java_pairing_1crypto_Bls12381Sha256_proof_1gen_1context_1set_1header,
    bbs_bls12_381_sha_256_proof_gen_context_set_header,
    Java_pairing_1crypto_Bls12381Sha256_proof_1gen_1context_1set_1signature,
    bbs_bls12_381_sha_256_proof_gen_context_set_signature,
    Java_pairing_1crypto_Bls12381Sha256_proof_1gen_1context_1set_1presentation_1header,
    bbs_bls12_381_sha_256_proof_gen_context_set_presentation_header,
    Java_pairing_1crypto_Bls12381Sha256_proof_1gen_1context_1set_1verify_1signature,
    bbs_bls12_381_sha_256_proof_gen_context_set_verify_signature,
    Java_pairing_1crypto_Bls12381Sha256_proof_1gen_1context_1add_1message,
    bbs_bls12_381_sha_256_proof_gen_context_add_message,
    Java_pairing_1crypto_Bls12381Sha256_proof_1gen_1context_1finish,
    bbs_bls12_381_sha_256_proof_gen_context_finish,
);

bbs_proof_gen_api_wrapper_generator!(
    Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1init,
    bbs_bls12_381_shake_256_proof_gen_context_init,
    Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1set_1public_1key,
    bbs_bls12_381_shake_256_proof_gen_context_set_public_key,
    Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1set_1header,
    bbs_bls12_381_shake_256_proof_gen_context_set_header,
    Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1set_1signature,
    bbs_bls12_381_shake_256_proof_gen_context_set_signature,
    Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1set_1presentation_1header,
    bbs_bls12_381_shake_256_proof_gen_context_set_presentation_header,
    Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1set_1verify_1signature,
    bbs_bls12_381_shake_256_proof_gen_context_set_verify_signature,
    Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1add_1message,
    bbs_bls12_381_shake_256_proof_gen_context_add_message,
    Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1finish,
    bbs_bls12_381_shake_256_proof_gen_context_finish,
);
