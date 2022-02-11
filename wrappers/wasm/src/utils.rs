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

use crate::dtos::*;
#[cfg(feature = "console_error")]
use console_error_panic_hook::*;
use pairing_crypto::bls12_381::*;
use pairing_crypto::schemes::*;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    //
    // NOTE - if this feature (console_error_panic_hook) is not enabled it will not fire
    #[cfg(feature = "console_error")]
    set_once();
}

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_u32(a: u32);
    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_many(a: &str, b: &str);
}

/// Digests the set of input messages and returns in the form of an internal
/// structure
pub fn digest_messages(messages: Vec<Vec<u8>>) -> Result<Vec<core::Message>, String> {
    if messages.len() < 1 {
        // TODO convert to wasm bindgen error
        return Err("Messages to sign empty, expected > 1".to_string());
    }

    Ok(messages.iter().map(|m| core::Message::hash(m)).collect())
}

pub fn digest_revealed_proof_messages(
    messages: HashMap<String, Vec<u8>>,
    total_message_count: usize,
) -> Result<Vec<(usize, Message)>, String> {
    let revealed_message_indexes: Vec<usize> = messages
        .iter()
        .map(|item| item.0.parse::<usize>().unwrap())
        .collect();

    if revealed_message_indexes
        .iter()
        .any(|r| *r >= total_message_count)
    {
        return Err(
            "Revealed message index out of bounds, value is >= total_message_count".to_string(),
        );
    }
    // TODO deal with the unwrap here and the error response
    Ok(messages
        .iter()
        .map(|(key, value)| (key.parse::<usize>().unwrap(), core::Message::hash(value)))
        .collect())
}

pub fn digest_proof_messages(
    messages: Vec<BbsDeriveProofRevealMessageRequest>,
) -> Result<Vec<core::ProofMessage>, String> {
    if messages.len() < 1 {
        // TODO convert to wasm bindgen error
        return Err("Messages to sign empty, expected > 1".to_string());
    }

    Ok(messages
        .iter()
        .map(|element| {
            let digested_message = core::Message::hash(element.value.clone());

            // Change this to an enum
            if element.reveal {
                return ProofMessage::Revealed(digested_message);
            } else {
                return ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(
                    digested_message,
                ));
            }
        })
        .collect())
}
