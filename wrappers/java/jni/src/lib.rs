use std::cell::RefCell;

use ffi_support::{ByteBuffer, ExternError};
// This is the interface to the JVM that we'll
// call the majority of our methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping this context
// and getting used after being GC'd.
use jni::objects::{JObject, JString};

// This is just a pointer. We'll be returning it from our function.
// We can't return one of the objects with lifetime information because the
// lifetime checker won't let us.
use jni::sys::{jbyte, jbyteArray, jint};

use pairing_crypto_c::api::key_gen::bbs_bls12381_generate_key_pair;

macro_rules! copy_to_jni {
    ($env:expr, $var:expr, $from:expr) => {
        if $env.set_byte_array_region($var, 0, $from).is_err() {
            return 0;
        }
    };
    ($env:expr, $var:expr, $from:expr, $val:expr) => {
        if $env.set_byte_array_region($var, 0, $from).is_err() {
            return $val;
        }
    };
}

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<String>>  = RefCell::new(None);
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_crypto_bbs_bls12381_get_last_error<'a>(
    env: JNIEnv<'a>,
    _: JObject,
) -> JString<'a> {
    let mut res = env.new_string("").unwrap();
    LAST_ERROR.with(|prev| {
        match &*prev.borrow() {
            Some(s) => res = env.new_string(s).unwrap(),
            None => (),
        };
    });
    res
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_crypto_bbs_bls12381_generate_key_pair(
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
    let result = bbs_bls12381_generate_key_pair(
        ikm.into(),
        key_info.into(),
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
