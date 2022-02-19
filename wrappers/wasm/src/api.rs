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
use crate::utils::*;

use pairing_crypto::bls12_381::*;
use pairing_crypto::schemes::*;
use std::convert::TryInto;
use wasm_bindgen::prelude::*;

/// Generate a BLS 12-381 key pair in the G1 field.
///
/// * seed: UIntArray with 32 elements
///
/// returned vector is the concatenation of first the private key (32 bytes)
/// followed by the public key (48) bytes.
#[wasm_bindgen(js_name = bls12381_GenerateG1KeyPair)]
pub async fn bls12381_generateg1key(seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    // Improves error output in JS based console.log() when built with debug feature enabled
    set_panic_hook();

    // Derive secret key from supplied seed otherwise generate a new seed and a derive a key from this
    // using the underlying RNG usually defaults to the OS provided RNG e.g in Node is node crypto
    let sk = match seed {
        Some(s) => SecretKey::from_seed(bbs::SECRET_KEY_SALT, s.to_vec()).unwrap(),
        None => SecretKey::random(bbs::SECRET_KEY_SALT).unwrap(),
    };

    // Derive the public key from the secret key
    let pk = PublicKeyVt::from(&sk);

    // Construct the JS DTO of the keypair to return
    let keypair = KeyPair {
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
#[wasm_bindgen(js_name = bls12381_GenerateG2KeyPair)]
pub async fn bls12381_generateg2key(seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    // Improves error output in JS based console.log() when built with debug feature enabled
    set_panic_hook();

    // Derive secret key from supplied seed otherwise generate a new seed and a derive a key from this
    // using the underlying RNG usually defaults to the OS provided RNG e.g in Node is node crypto
    let sk = match seed {
        Some(s) => SecretKey::from_seed(bbs::SECRET_KEY_SALT, s.to_vec()).unwrap(),
        None => SecretKey::random(bbs::SECRET_KEY_SALT).unwrap(),
    };
    // Derive the public key from the secret key
    let pk = PublicKey::from(&sk);

    // Construct the JS DTO of the keypair to return
    let keypair = KeyPair {
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
#[wasm_bindgen(js_name = bls12381_Bbs_SignG1)]
pub async fn bls12381_bbs_signg1(request: JsValue) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // Improves error output in JS based console.log() when built with debug feature enabled
    set_panic_hook();
    // Cast the supplied JSON request into a rust struct
    let request: BbsSignRequest = request.try_into()?;

    // Parse public key from request
    let sk = match SecretKey::from_vec(request.secretKey) {
        Ok(result) => result,
        Err(e) => return Err(serde_wasm_bindgen::Error::new(format!("{:?}", e))),
    };

    // Derive the public key from the secret key
    let pk = PublicKey::from(&sk);

    // Digest the supplied messages
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
#[wasm_bindgen(js_name = bls12381_Bbs_VerifyG1)]
pub async fn bls12381_bbs_verifyg1(request: JsValue) -> Result<JsValue, JsValue> {
    // Improves error output in JS based console.log() when built with debug feature enabled
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

    // Parse public key from request
    let pk = match PublicKey::from_vec(request.publicKey) {
        Ok(result) => result,
        Err(e) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: Some(format!("{:?}", e)),
            })
            .unwrap())
        }
    };

    // Digest the supplied messages
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

    // Parse signature from request
    let signature = match bbs::Signature::from_vec(request.signature) {
        Ok(result) => result,
        Err(e) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: Some(format!("{:?}", e)),
            })
            .unwrap())
        }
    };

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
/// {
///     "publicKey": Vec<u8>, // Uint8Array of bytes representing the public key
///     "signature": Vec<u8>,
///     "presentationMessage": Vec<u8>,
///     "messages": [{ // Note this array is considered ordered and MUST match the order in which the messages were signed
///         "value": Vec<u8>, // Uint8Array of raw bytes representing the message
///         "reveal": boolean // indicates whether or not to reveal the message in the derived proof
///     }]
/// }
///
/// Returned value is a byte array which is the produced proof (variable length)
#[wasm_bindgen(js_name = bls12381_Bbs_DeriveProofG1)]
pub async fn bls12381_bbs_deriveproofg1(
    request: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // Improves error output in JS based console.log() when built with debug feature enabled
    set_panic_hook();

    // Cast the JSON request into a rust struct
    let request: BbsDeriveProofRequest = request.try_into()?;

    // Parse public key from request
    let pk = match PublicKey::from_vec(request.publicKey) {
        Ok(result) => result,
        Err(e) => return Err(serde_wasm_bindgen::Error::new(format!("{:?}", e))),
    };

    // Parse signature from request
    let signature = match bbs::Signature::from_vec(request.signature) {
        Ok(result) => result,
        Err(e) => return Err(serde_wasm_bindgen::Error::new(format!("{:?}", e))),
    };

    // Digest the supplied messages
    let messages = digest_messages(
        request
            .messages
            .iter()
            .map(|element| element.value.clone())
            .collect(),
    )
    .unwrap();

    // Use generators derived from the signers public key
    // TODO this approach is likely to change soon
    let generators = bbs::MessageGenerators::from_public_key(pk, messages.len());

    // Verify the signature to check the messages supplied are valid
    match signature.verify(&pk, &generators, &messages) {
        false => {
            return Err(serde_wasm_bindgen::Error::new(
                "Invalid signature, unable to verify",
            ))
        }
        true => {}
    };

    // Digest the supplied messages
    let proof_messages: Vec<ProofMessage> = match digest_proof_messages(request.messages) {
        Ok(messages) => messages,
        Err(err) => return Err(serde_wasm_bindgen::Error::new(err.as_str())),
    };

    let presentation_message = core::PresentationMessage::hash(request.presentationMessage);

    let proof = bbs::Prover::derive_signature_pok(
        signature,
        &generators,
        presentation_message,
        &proof_messages,
    )
    .unwrap();

    Ok(serde_wasm_bindgen::to_value(&proof.to_bytes()).unwrap())
}

/// Verifies a signature proof of knowledge proof
///
/// * request: JSON encoded request TODO
///
/// {
///     "publicKey": Vec<u8>, // Uint8Array of bytes representing the public key
///     "proof": Vec<u8>,
///     "presentationMessage": Vec<u8>,
///     "totalMessageCount": usize,
///     "messages": {
///         number: {
///            "value": Vec<u8> // Uint8Array of raw bytes representing the message
///         }
///     }]
/// }
///
/// Returned value is a byte array which is the produced proof (variable length)
#[wasm_bindgen(js_name = bls12381_Bbs_VerifyProofG1)]
pub async fn bls12381_bbs_verifyproofg1(
    request: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // Improves error output in JS based console.log() when built with debug feature enabled
    set_panic_hook();

    // Cast the JSON request into a rust struct
    let request: BbsVerifyProofRequest = request.try_into()?;

    // Digest the revealed proof messages
    let messages: Vec<(usize, Message)> =
        digest_revealed_proof_messages(request.messages, request.totalMessageCount).unwrap();

    // Parse public key from request
    let pk = match PublicKey::from_vec(request.publicKey) {
        Ok(result) => result,
        Err(e) => return Err(serde_wasm_bindgen::Error::new(format!("{:?}", e))),
    };

    // Use generators derived from the signers public key
    // TODO this approach is likely to change soon
    let generators = bbs::MessageGenerators::from_public_key(pk, request.totalMessageCount);

    let proof = bbs::PokSignatureProof::from_bytes(request.proof).unwrap();

    let presentation_message = PresentationMessage::hash(request.presentationMessage);

    match bbs::Verifier::verify_signature_pok(
        messages.as_slice(),
        pk,
        proof,
        &generators,
        presentation_message,
    ) {
        Ok(result) => return Ok(JsValue::from(result)),
        Err(_) => return Ok(JsValue::from(false)), // TODO review this response structure
    }
}
