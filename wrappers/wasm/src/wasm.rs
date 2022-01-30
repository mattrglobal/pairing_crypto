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
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

wasm_impl!(
    /// Convenience struct for interfacing with JS.
    /// Option allows both of the keys to be JS::null
    /// or only one of them set.
    #[allow(non_snake_case)]
    #[derive(Debug, Deserialize, Serialize)]
    BlsKeyPair,
    publicKey: Option<Vec<u8>>,
    secretKey: Option<Vec<u8>>
);

/// Generate a BLS 12-381 key pair in the G1 field.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (32 bytes)
/// followed by the public key (96) bytes.
#[wasm_bindgen(js_name = bls12381GenerateG1KeyPair)]
pub fn bls12_381_generate_g1_key(seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    let seed_data = match seed {
        Some(s) => s.to_vec(),
        None => {
            let mut rng = thread_rng();
            let mut s = vec![0u8, 32];
            rng.fill_bytes(s.as_mut_slice());
            s
        }
    };

    let sk = bls::SecretKey::hash(seed_data).unwrap();
    let pk = bls::PublicKeyVt::from(&sk);

    let keypair = BlsKeyPair {
        publicKey: Some(pk.to_bytes().to_vec()),
        secretKey: Some(sk.to_bytes().to_vec()),
    };
    Ok(serde_wasm_bindgen::to_value(&keypair).unwrap())
}

/// Generate a BLS 12-381 key pair in the G2 field.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (32 bytes)
/// followed by the public key (96) bytes.
#[wasm_bindgen(js_name = bls12381GenerateG2KeyPair)]
pub fn bls12_381_generate_g2_key(seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    let seed_data = match seed {
        Some(s) => s.to_vec(),
        None => {
            let mut rng = thread_rng();
            let mut s = vec![0u8, 32];
            rng.fill_bytes(s.as_mut_slice());
            s
        }
    };

    let sk = bls::SecretKey::hash(seed_data).unwrap();
    let pk = bls::PublicKey::from(&sk);

    let keypair = BlsKeyPair {
        publicKey: Some(pk.to_bytes().to_vec()),
        secretKey: Some(sk.to_bytes().to_vec()),
    };
    Ok(serde_wasm_bindgen::to_value(&keypair).unwrap())
}
