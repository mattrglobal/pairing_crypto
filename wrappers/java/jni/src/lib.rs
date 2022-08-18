use std::cell::RefCell;

// This is the interface to the JVM that we'll
// call the majority of our methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping this context
// and getting used after being GC'd.
use jni::objects::{JObject, JString};

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

pub(crate) fn update_last_error(m: &str) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(m.to_string());
    })
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

pub mod bbs;
