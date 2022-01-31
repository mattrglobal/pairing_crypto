/*
 * Copyright 2020
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

use pairing_crypto::schemes::*;
use std::convert::TryFrom;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    //
    // NOTE - if this feature (console_error_panic_hook) is not enabled it will not fire
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Digests the set of input messages and returns in the form of an internal
/// structure
pub fn digest_messages(messages: Vec<Vec<u8>>) -> Result<Vec<core::Message>, String> {
    if messages.len() < 1 {
        return Err("Messages to sign empty, expected > 1".to_string());
    }

    Ok(messages.iter().map(|m| core::Message::hash(m)).collect())
}

/// Convert an input vector into a byte array
pub fn vec_to_byte_array<const N: usize>(vec: Vec<u8>) -> Result<[u8; N], String> {
    match <[u8; N]>::try_from(vec) {
        Ok(result) => Ok(result),
        Err(_) => Err("Input data length incorrect".to_string()),
    }
}
