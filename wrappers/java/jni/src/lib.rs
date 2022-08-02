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
use jni::sys::{jboolean, jbyte, jbyteArray, jint, jlong};

use pairing_crypto_c::{
    api::{
        derive_proof::{
            bbs_bls12381_derive_proof_context_add_message,
            bbs_bls12381_derive_proof_context_finish,
            bbs_bls12381_derive_proof_context_init,
            bbs_bls12381_derive_proof_context_set_header,
            bbs_bls12381_derive_proof_context_set_presentation_message,
            bbs_bls12381_derive_proof_context_set_public_key,
            bbs_bls12381_derive_proof_context_set_signature,
        },
        get_proof_size::bbs_bls12381_get_proof_size,
        key_gen::bbs_bls12381_generate_key_pair,
        sign::{
            bbs_bls12381_sign_context_add_message,
            bbs_bls12381_sign_context_finish,
            bbs_bls12381_sign_context_init,
            bbs_bls12381_sign_context_set_header,
            bbs_bls12381_sign_context_set_public_key,
            bbs_bls12381_sign_context_set_secret_key,
        },
        verify::{
            bbs_bls12381_verify_context_add_message,
            bbs_bls12381_verify_context_finish,
            bbs_bls12381_verify_context_init,
            bbs_bls12381_verify_context_set_header,
            bbs_bls12381_verify_context_set_public_key,
            bbs_bls12381_verify_context_set_signature,
        },
        verify_proof::{
            bbs_bls12381_verify_proof_context_add_message,
            bbs_bls12381_verify_proof_context_finish,
            bbs_bls12381_verify_proof_context_init,
            bbs_bls12381_verify_proof_context_set_header,
            bbs_bls12381_verify_proof_context_set_presentation_message,
            bbs_bls12381_verify_proof_context_set_proof,
            bbs_bls12381_verify_proof_context_set_public_key,
            bbs_bls12381_verify_proof_context_set_total_message_count,
        },
    },
    dtos::ByteArray,
    BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
    BBS_BLS12381G1_SECRET_KEY_LENGTH,
    BBS_BLS12381G1_SIGNATURE_LENGTH,
};

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

fn update_last_error(m: &str) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(m.to_string());
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1generate_1key_1pair(
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

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1sign_1context_1init(
    _: JNIEnv,
    _: JObject,
) -> jlong {
    let mut error = ExternError::success();
    bbs_bls12381_sign_context_init(&mut error) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1sign_1context_1set_1secret_1key(
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
                let byte_array = ByteArray::from(s);
                bbs_bls12381_sign_context_set_secret_key(
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
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1sign_1context_1set_1public_1key(
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
                let byte_array = ByteArray::from(s);
                bbs_bls12381_sign_context_set_public_key(
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
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1sign_1context_1set_1header(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    header: jbyteArray,
) -> jint {
    match env.convert_byte_array(header) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_bls12381_sign_context_set_header(
                handle as u64,
                &byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1sign_1context_1add_1message(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_bls12381_sign_context_add_message(
                handle as u64,
                &byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1sign_1context_1finish(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    signature: jbyteArray,
) -> jint {
    let mut error = ExternError::success();
    let mut sig = ByteBuffer::from_vec(vec![]);
    let result =
        bbs_bls12381_sign_context_finish(handle as u64, &mut sig, &mut error);
    if result != 0 {
        return result;
    }
    let sig: Vec<i8> =
        sig.destroy_into_vec().iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, signature, sig.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1context_1init(
    _: JNIEnv,
    _: JObject,
) -> jlong {
    let mut error = ExternError::success();
    bbs_bls12381_verify_context_init(&mut error) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1context_1set_1public_1key(
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
                let byte_array = ByteArray::from(s);
                bbs_bls12381_verify_context_set_public_key(
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
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1context_1set_1header(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    header: jbyteArray,
) -> jint {
    match env.convert_byte_array(header) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_bls12381_verify_context_set_header(
                handle as u64,
                &byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1context_1add_1message(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_bls12381_verify_context_add_message(
                handle as u64,
                &byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1context_1set_1signature(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    signature: jbyteArray,
) -> jint {
    match env.convert_byte_array(signature) {
        Err(_) => 1,
        Ok(s) => {
            if s.len() != BBS_BLS12381G1_SIGNATURE_LENGTH {
                2
            } else {
                let mut error = ExternError::success();
                let byte_array = ByteArray::from(s);
                bbs_bls12381_verify_context_set_signature(
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
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1context_1finish(
    _: JNIEnv,
    _: JObject,
    handle: jlong,
) -> jint {
    let mut error = ExternError::success();
    bbs_bls12381_verify_context_finish(handle as u64, &mut error)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1derive_1proof_1context_1init(
    _: JNIEnv,
    _: JObject,
) -> jlong {
    let mut error = ExternError::success();
    bbs_bls12381_derive_proof_context_init(&mut error) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1derive_1proof_1context_1set_1public_1key(
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
                let byte_array = ByteArray::from(s);
                bbs_bls12381_derive_proof_context_set_public_key(
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
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1derive_1proof_1context_1set_1header(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    header: jbyteArray,
) -> jint {
    match env.convert_byte_array(header) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_bls12381_derive_proof_context_set_header(
                handle as u64,
                &byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1derive_1proof_1context_1set_1signature(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    signature: jbyteArray,
) -> jint {
    match env.convert_byte_array(signature) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            let res = bbs_bls12381_derive_proof_context_set_signature(
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
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1derive_1proof_1context_1set_1presentation_1message(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    presentation_message: jbyteArray,
) -> jint {
    match env.convert_byte_array(presentation_message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_bls12381_derive_proof_context_set_presentation_message(
                handle as u64,
                &byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1derive_1proof_1context_1add_1proof_1message(
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
            let byte_array = ByteArray::from(s);
            bbs_bls12381_derive_proof_context_add_message(
                handle as u64,
                reveal != 0,
                &byte_array,
                &mut error,
            )
        }
    }
}

/// Caller should treat negative return values as error.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1proof_1size(
    _: JNIEnv,
    _: JObject,
    num_undisclosed_messages: jint,
) -> jint {
    bbs_bls12381_get_proof_size(num_undisclosed_messages as usize)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1derive_1proof_1context_1finish(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    proof: jbyteArray,
) -> jint {
    let mut error = ExternError::success();
    let mut p = ByteBuffer::from_vec(vec![]);
    let res = bbs_bls12381_derive_proof_context_finish(
        handle as u64,
        &mut p,
        &mut error,
    );
    if res != 0 {
        return res;
    }
    let res = p.destroy_into_vec();
    let pp: Vec<jbyte> = res.iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, proof, pp.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1proof_1context_1init(
    _: JNIEnv,
    _: JObject,
) -> jlong {
    let mut error = ExternError::success();
    bbs_bls12381_verify_proof_context_init(&mut error) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1proof_1context_1set_1public_1key(
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
                let byte_array = ByteArray::from(s);
                bbs_bls12381_verify_proof_context_set_public_key(
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
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1proof_1context_1set_1header(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    header: jbyteArray,
) -> jint {
    match env.convert_byte_array(header) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_bls12381_verify_proof_context_set_header(
                handle as u64,
                &byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1proof_1context_1set_1proof(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    proof: jbyteArray,
) -> jint {
    match env.convert_byte_array(proof) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from_slice(s.as_slice());
            let res = bbs_bls12381_verify_proof_context_set_proof(
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
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1proof_1context_1set_1presentation_1message(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    presentation_message: jbyteArray,
) -> jint {
    match env.convert_byte_array(presentation_message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_bls12381_verify_proof_context_set_presentation_message(
                handle as u64,
                &byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1proof_1context_1set_1total_1message_1count(
    _: JNIEnv,
    _: JObject,
    handle: jlong,
    total_message_count: jint,
) -> jint {
    match usize::try_from(total_message_count) {
        Err(_) => 1,
        Ok(c) => {
            let mut error = ExternError::success();
            bbs_bls12381_verify_proof_context_set_total_message_count(
                handle as u64,
                c,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1proof_1context_1add_1message(
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
            let byte_array = ByteArray::from(s);
            match usize::try_from(index) {
                Err(_) => 1,
                Ok(i) => bbs_bls12381_verify_proof_context_add_message(
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
pub extern "C" fn Java_pairing_1crypto_Bbs_bbs_1bls12381_1verify_1proof_1context_1finish(
    _: JNIEnv,
    _: JObject,
    handle: jlong,
) -> jint {
    let mut error = ExternError::success();
    bbs_bls12381_verify_proof_context_finish(handle as u64, &mut error)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bbs_get_1last_1error<'a>(
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
