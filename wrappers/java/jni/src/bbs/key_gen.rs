use ffi_support::{ByteBuffer, ExternError};
// This is the interface to the JVM that we'll
// call the majority of our methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping this context
// and getting used after being GC'd.
use jni::objects::JObject;

// This is just a pointer. We'll be returning it from our function.
// We can't return one of the objects with lifetime information because the
// lifetime checker won't let us.
use jni::sys::{jbyte, jbyteArray, jint};

use pairing_crypto_c::{
    bbs::key_gen::{
        bbs_bls12_381_sha_256_generate_key_pair,
        bbs_bls12_381_shake_256_generate_key_pair,
    },
    dtos::ByteArray,
};

macro_rules! bbs_key_gen_api_wrapper_generator {
    (
        $java_wrapper_generate_key_pair_fn:ident,
        $generate_key_pair_fn:ident
    ) => {
        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_generate_key_pair_fn(
            env: JNIEnv,
            _: JObject,
            ikm: jbyteArray,
            key_info: jbyteArray,
            public_key: jbyteArray,
            secret_key: jbyteArray,
        ) -> jint {
            let ikm = match env.convert_byte_array(ikm) {
                Err(_) => return 1,
                Ok(s) => s,
            };
            let key_info = match env.convert_byte_array(key_info) {
                Err(_) => return 1,
                Ok(s) => s,
            };
            let mut error = ExternError::success();
            let mut sk = ByteBuffer::from_vec(vec![]);
            let mut pk = ByteBuffer::from_vec(vec![]);
            let result = $generate_key_pair_fn(
                ByteArray::from(&ikm),
                ByteArray::from(&key_info),
                &mut sk,
                &mut pk,
                &mut error,
            );
            if result != 0 {
                return result;
            }
            let pk: Vec<i8> =
                pk.destroy_into_vec().iter().map(|b| *b as jbyte).collect();
            let sk: Vec<i8> =
                sk.destroy_into_vec().iter().map(|b| *b as jbyte).collect();
            copy_to_jni!(env, public_key, pk.as_slice());
            copy_to_jni!(env, secret_key, sk.as_slice());
            0
        }
    };
}

bbs_key_gen_api_wrapper_generator!(
    Java_pairing_1crypto_Bls12381Sha256_generate_1key_1pair,
    bbs_bls12_381_sha_256_generate_key_pair
);
bbs_key_gen_api_wrapper_generator!(
    Java_pairing_1crypto_Bls12381Shake256_generate_1key_1pair,
    bbs_bls12_381_shake_256_generate_key_pair
);
