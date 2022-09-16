use ffi_support::{ByteBuffer, ExternError};
use jni::{
    objects::JObject,
    sys::{jbyte, jbyteArray, jint, jlong},
    JNIEnv,
};

use pairing_crypto_c::{
    bbs::{
        sign::{
            bbs_bls12_381_sha_256_sign_context_add_message,
            bbs_bls12_381_sha_256_sign_context_finish,
            bbs_bls12_381_sha_256_sign_context_init,
            bbs_bls12_381_sha_256_sign_context_set_header,
            bbs_bls12_381_sha_256_sign_context_set_public_key,
            bbs_bls12_381_sha_256_sign_context_set_secret_key,
            bbs_bls12_381_shake_256_sign_context_add_message,
            bbs_bls12_381_shake_256_sign_context_finish,
            bbs_bls12_381_shake_256_sign_context_init,
            bbs_bls12_381_shake_256_sign_context_set_header,
            bbs_bls12_381_shake_256_sign_context_set_public_key,
            bbs_bls12_381_shake_256_sign_context_set_secret_key,
        },
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH, BBS_BLS12381G1_SECRET_KEY_LENGTH,
    },
    dtos::ByteArray,
};

macro_rules! bbs_sign_api_wrapper_generator {
    (
        $java_wrapper_init_fn:ident,
        $init_fn:ident,
        $java_wrapper_set_secret_key_fn:ident,
        $set_secret_key_fn:ident,
        $java_wrapper_set_public_key_fn:ident,
        $set_public_key_fn:ident,
        $java_wrapper_set_header_fn:ident,
        $set_header_fn:ident,
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
        pub extern "C" fn $java_wrapper_set_secret_key_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            secret_key: jbyteArray,
        ) -> jint {
            match env.convert_byte_array(secret_key) {
                Err(_) => 1,
                Ok(s) => {
                    if s.len() != BBS_BLS12381G1_SECRET_KEY_LENGTH {
                        2
                    } else {
                        let mut error = ExternError::success();
                        let byte_array = ByteArray::from(&s);
                        $set_secret_key_fn(
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
        pub extern "C" fn $java_wrapper_add_message_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            message: jbyteArray,
        ) -> jint {
            match env.convert_byte_array(message) {
                Err(_) => 1,
                Ok(s) => {
                    let mut error = ExternError::success();
                    let byte_array = ByteArray::from(&s);
                    $add_message_fn(handle as u64, &byte_array, &mut error)
                }
            }
        }

        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_finish_fn(
            env: JNIEnv,
            _: JObject,
            handle: jlong,
            signature: jbyteArray,
        ) -> jint {
            let mut error = ExternError::success();
            let mut sig = ByteBuffer::from_vec(vec![]);
            let result = $finish_fn(handle as u64, &mut sig, &mut error);
            if result != 0 {
                return result;
            }
            let sig: Vec<i8> =
                sig.destroy_into_vec().iter().map(|b| *b as jbyte).collect();
            copy_to_jni!(env, signature, sig.as_slice());
            0
        }
    };
}

bbs_sign_api_wrapper_generator!(
    Java_pairing_1crypto_Bls12381Sha256_sign_1context_1init,
    bbs_bls12_381_sha_256_sign_context_init,
    Java_pairing_1crypto_Bls12381Sha256_sign_1context_1set_1secret_1key,
    bbs_bls12_381_sha_256_sign_context_set_secret_key,
    Java_pairing_1crypto_Bls12381Sha256_sign_1context_1set_1public_1key,
    bbs_bls12_381_sha_256_sign_context_set_public_key,
    Java_pairing_1crypto_Bls12381Sha256_sign_1context_1set_1header,
    bbs_bls12_381_sha_256_sign_context_set_header,
    Java_pairing_1crypto_Bls12381Sha256_sign_1context_1add_1message,
    bbs_bls12_381_sha_256_sign_context_add_message,
    Java_pairing_1crypto_Bls12381Sha256_sign_1context_1finish,
    bbs_bls12_381_sha_256_sign_context_finish,
);

bbs_sign_api_wrapper_generator!(
    Java_pairing_1crypto_Bls12381Shake256_sign_1context_1init,
    bbs_bls12_381_shake_256_sign_context_init,
    Java_pairing_1crypto_Bls12381Shake256_sign_1context_1set_1secret_1key,
    bbs_bls12_381_shake_256_sign_context_set_secret_key,
    Java_pairing_1crypto_Bls12381Shake256_sign_1context_1set_1public_1key,
    bbs_bls12_381_shake_256_sign_context_set_public_key,
    Java_pairing_1crypto_Bls12381Shake256_sign_1context_1set_1header,
    bbs_bls12_381_shake_256_sign_context_set_header,
    Java_pairing_1crypto_Bls12381Shake256_sign_1context_1add_1message,
    bbs_bls12_381_shake_256_sign_context_add_message,
    Java_pairing_1crypto_Bls12381Shake256_sign_1context_1finish,
    bbs_bls12_381_shake_256_sign_context_finish,
);
