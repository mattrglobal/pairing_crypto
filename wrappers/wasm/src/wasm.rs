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

use crate::utils::*;

use pairing_crypto::schemes::*;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use wasm_bindgen::prelude::*;

// Macro for interpreting JSON object as a RUST struct
wasm_impl!(
    /// Convenience struct for interfacing with JS.
    /// Option allows both of the keys to be JS::null
    /// or only one of them set.
    #[allow(non_snake_case)]
    #[derive(Debug, Deserialize, Serialize)]
    BlsKeyPair,
    publicKey: Vec<u8>,
    secretKey: Option<Vec<u8>>
);

// Macro for interpreting JSON object as a RUST struct
wasm_impl!(BbsSignRequest, secretKey: Vec<u8>, messages: Vec<Vec<u8>>);

// Macro for interpreting JSON object as a RUST struct
wasm_impl!(
    BbsVerifyRequest,
    publicKey: Vec<u8>,
    messages: Vec<Vec<u8>>,
    signature: Vec<u8>
);

// Macro for interpreting JSON object as a RUST struct
wasm_impl!(BbsVerifyResponse, verified: bool, error: Option<String>);

// Macro for interpreting JSON object as a RUST struct
wasm_impl!(
    BbsDeriveProofRequest,
    publicKey: Vec<u8>,
    messages: Vec<Vec<u8>>,
    signature: Vec<u8>,
    revealedIndicies: Vec<u8>
);

/// Generate a BLS 12-381 key pair in the G1 field.
///
/// * seed: UIntArray with 32 elements
///
/// returned vector is the concatenation of first the private key (32 bytes)
/// followed by the public key (48) bytes.
#[wasm_bindgen(js_name = bls12381GenerateG1KeyPair)]
pub async fn bls12_381_generate_g1_key(seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let seed_data = match seed {
        Some(s) => s.to_vec(),
        None => {
            let mut rng = thread_rng();
            let mut s = vec![0u8, 32];
            rng.fill_bytes(s.as_mut_slice());
            s
        }
    };

    let sk = bls::SecretKey::from_seed(seed_data).unwrap();
    let pk = bls::PublicKeyVt::from(&sk);

    let keypair = BlsKeyPair {
        publicKey: pk.to_bytes().to_vec(),
        secretKey: Some(sk.to_bytes().to_vec()),
    };
    Ok(serde_wasm_bindgen::to_value(&keypair).unwrap())
}

/// Generate a BLS 12-381 key pair in the G2 field.
///
/// * seed: UIntArray with 32 elements
///
/// Returned value is a byte array which is the concatenation of first the private key (32 bytes)
/// followed by the public key (96) bytes.
#[wasm_bindgen(js_name = bls12381GenerateG2KeyPair)]
pub async fn bls12_381_generate_g2_key(seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let seed_data = match seed {
        Some(s) => s.to_vec(),
        None => {
            let mut rng = thread_rng();
            let mut s = vec![0u8, 32];
            rng.fill_bytes(s.as_mut_slice());
            s
        }
    };

    let sk = bls::SecretKey::from_seed(seed_data).unwrap();
    let pk = bls::PublicKey::from(&sk);

    let keypair = BlsKeyPair {
        publicKey: pk.to_bytes().to_vec(),
        secretKey: Some(sk.to_bytes().to_vec()),
    };
    Ok(serde_wasm_bindgen::to_value(&keypair).unwrap())
}

/// Create (Signs) a BBS Signature in the G1 sub-group using a key pair based in G2
///
/// * request: JSON encoded request containing a byte array of messages to be signed and a BLS12-381 key pair
///
/// Returned value is a byte array which is the produced signature (112 bytes)
#[wasm_bindgen(js_name = bls12381BbsSignG1)]
pub async fn bls12_381_bbs_sign_g1(request: JsValue) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    // Cast the JSON request into a rust struct
    let request: BbsSignRequest = request.try_into()?;

    // Convert to byte array and check proper length
    let secret_key_byte_array = match vec_to_byte_array::<32>(request.secretKey) {
        Ok(result) => result,
        Err(_) => {
            return Err(serde_wasm_bindgen::Error::new(
                "Secret key length incorrect expected 32 bytes",
            ))
        }
    };

    // Get the secret key from the raw bytes
    // TODO dont use general unwrap here
    let sk = bls::SecretKey::from_bytes(&secret_key_byte_array).unwrap();

    // Derive the public key from the secret key
    // TODO public key isn't really needed in the request to this API could get away with dropping it?
    let pk = bls::PublicKey::from(&sk);

    // Digest the supplied messages
    // TODO review digest algorithm being used
    let messages: Vec<core::Message> = match digest_messages(request.messages) {
        Ok(messages) => messages,
        Err(_) => {
            return Err(serde_wasm_bindgen::Error::new(
                "Messages to sign empty, expected > 1",
            ))
        }
    };

    // Use generators derived from the signers public key
    // TODO this approach is likely to change soon
    let generators = bbs::MessageGenerators::from_public_key(pk, messages.len());

    // Produce the signature and return
    match bbs::Signature::new(&sk, &generators, &messages) {
        Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).unwrap()),
        Err(_e) => Err(serde_wasm_bindgen::Error::new("Failed to sign")),
    }
}

/// Verifies a BBS Signature in the G1 sub-group using a public key based in G2
///
/// * request: JSON encoded request containing a byte array of the signature to verify, the array of byte arrays representing the
/// messages protected by the signature and the BLS12-381 based public key in G2
///
/// Returned value is JSON structure with a boolean value indicating whether the signature was verified and
/// if not any details on the error available
#[wasm_bindgen(js_name = bls12381BbsVerifyG1)]
pub async fn bls12_381_bbs_verify_g1(request: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();
    // Cast the JSON request into a rust struct
    let res = request.try_into();

    let request: BbsVerifyRequest = match res {
        Ok(result) => result,
        Err(e) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: Some(format!("{:?}", e)),
            })
            .unwrap())
        }
    };

    // Convert to byte array and check proper length
    // TODO should not be hard coded here
    let public_key_byte_array = match vec_to_byte_array::<96>(request.publicKey) {
        Ok(result) => result,
        Err(_) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: Some("Public key length incorrect expected 96 bytes".to_string()),
            })
            .unwrap())
        }
    };

    // Get the secret key from the raw bytes
    // TODO dont use general unwrap here
    let pk = bls::PublicKey::from_bytes(&public_key_byte_array).unwrap();

    // Digest the supplied messages
    // TODO review digest algorithm being used
    let messages: Vec<core::Message> = match digest_messages(request.messages) {
        Ok(messages) => messages,
        Err(err) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: Some(err.as_str().to_string()),
            })
            .unwrap())
        }
    };

    // Use generators derived from the signers public key
    // TODO this approach is likely to change soon
    let generators = bbs::MessageGenerators::from_public_key(pk, messages.len());

    // Convert to byte array and check proper length of signature
    // TODO this should not be hard coded like this
    let signature_byte_array = match vec_to_byte_array::<112>(request.signature) {
        Ok(result) => result,
        Err(_) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: Some("Signature incorrect length, expecting 112 bytes".to_string()),
            })
            .unwrap())
        }
    };

    // TODO should not just be using unwrap here
    let signature = bbs::Signature::from_bytes(&signature_byte_array).unwrap();

    match signature.verify(&pk, &generators, &messages) {
        true => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: true,
                error: None,
            })
            .unwrap())
        }
        false => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: None,
            })
            .unwrap())
        }
    }
}

/// Derives signature proof of knowledge proof from a supplied BBS Signature in the
/// G1 subgroup
///
/// * request: JSON encoded request containing a byte array of the signature to derive
/// the proof from, an ORDERED array of byte arrays representing the messages protected
/// by the signature, an array indicating which messages to reveal in the derived proof
/// and the BLS12-381 based public key in G2 associated to the original signer of the
/// signature
///
/// Returned value is a byte array which is the produced proof (variable length)
#[wasm_bindgen(js_name = bls12381BbsDeriveProofG1)]
pub async fn bls12_381_bbs_derive_proof_g1(
    request: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    // Cast the JSON request into a rust struct
    let request: BbsDeriveProofRequest = request.try_into()?;

    // Convert to byte array and check proper length
    // TODO should not be hard coded here
    let public_key_byte_array = match vec_to_byte_array::<96>(request.publicKey) {
        Ok(result) => result,
        Err(_) => {
            return Err(serde_wasm_bindgen::Error::new(
                "Public key length incorrect expected 96 bytes",
            ))
        }
    };

    // Digest the supplied messages
    let messages: Vec<core::Message> = match digest_messages(request.messages) {
        Ok(messages) => messages,
        Err(err) => return Err(serde_wasm_bindgen::Error::new(err.as_str())),
    };

    // Get the secret key from the raw bytes
    // TODO dont use general unwrap here
    let pk = bls::PublicKey::from_bytes(&public_key_byte_array).unwrap();

    // Use generators derived from the signers public key
    // TODO this approach is likely to change soon
    let _generators = bbs::MessageGenerators::from_public_key(pk, messages.len());

    // Convert to byte array and check proper length of signature
    // TODO this should not be hard coded like this
    let signature_byte_array = match vec_to_byte_array::<112>(request.signature) {
        Ok(result) => result,
        Err(_) => {
            return Err(serde_wasm_bindgen::Error::new(
                "Signature incorrect length, expecting 112 bytes",
            ))
        }
    };

    // TODO should not just be using unwrap here
    let _signature = bbs::Signature::from_bytes(&signature_byte_array).unwrap();

    Ok(JsValue::from("TODO"))
}
