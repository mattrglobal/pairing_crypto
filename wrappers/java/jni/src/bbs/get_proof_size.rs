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
use jni::sys::jint;

use pairing_crypto_c::bbs::get_proof_size::{
    bbs_bls12_381_sha_256_get_proof_size,
    bbs_bls12_381_shake_256_get_proof_size,
};

macro_rules! bbs_get_proof_size_api_wrapper_generator {
    (
        $java_wrapper_get_proof_size_fn:ident,
        $get_proof_size_fn:ident
    ) => {
        /// Caller should treat negative return values as error.
        #[allow(non_snake_case)]
        #[no_mangle]
        pub extern "C" fn $java_wrapper_get_proof_size_fn(
            _: JNIEnv,
            _: JObject,
            num_undisclosed_messages: jint,
        ) -> jint {
            $get_proof_size_fn(num_undisclosed_messages as usize)
        }
    };
}

bbs_get_proof_size_api_wrapper_generator!(
    Java_pairing_1crypto_Bls12381Sha256_get_1proof_1size,
    bbs_bls12_381_sha_256_get_proof_size
);

bbs_get_proof_size_api_wrapper_generator!(
    Java_pairing_1crypto_Bls12381Shake256_get_1proof_1size,
    bbs_bls12_381_shake_256_get_proof_size
);
