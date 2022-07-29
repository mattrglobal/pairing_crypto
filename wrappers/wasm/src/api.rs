// Copyright 2020
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ------------------------------------------------------------------------------

use crate::{dtos::*, utils::*};
use core::convert::{TryFrom, TryInto};
use pairing_crypto::bbs::ciphersuites::bls12_381::{
    proof_gen,
    proof_verify,
    sign,
    verify,
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
    KeyPair as PairingCryptoKeyPair,
    BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
    BBS_BLS12381G1_SECRET_KEY_LENGTH,
    BBS_BLS12381G1_SIGNATURE_LENGTH,
};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

/// Generate a BBS key pair on BLS 12-381 curve.
///
/// * request: JSON encoded request optionally containing
///             - IKM: Input Key Material (if not supplied a random value will
///               be generated via RNG)
///             - key_info: Key information
///
/// Returned value is a byte array which is the concatenation of first the
/// private key (32 bytes) followed by the public key (96) bytes.
#[wasm_bindgen(js_name = bbs_bls12381_generate_key_pair)]
pub async fn bbs_bls12381_generate_key_pair(
    request: JsValue,
) -> Result<JsValue, JsValue> {
    // Improves error output in JS based console.log() when built with debug
    // feature enabled
    set_panic_hook();

    // Cast the supplied JSON request into a rust struct
    let request: KeyGenerationRequestDto = request.try_into()?;

    // // Derive secret key from supplied IKM and key information metadata.
    let key_pair = match request.ikm {
        Some(ikm) => PairingCryptoKeyPair::new(
            &ikm,
            request.keyInfo.as_ref().map(Vec::as_ref),
        )
        .unwrap(),
        None => PairingCryptoKeyPair::random(
            &mut OsRng::default(),
            request.keyInfo.as_ref().map(Vec::as_ref),
        )
        .unwrap(),
    };

    // Construct the JS DTO of the key pair to return
    let keypair = KeyPair {
        secretKey: Some(key_pair.secret_key.to_bytes().to_vec()),
        publicKey: key_pair.public_key.to_octets().to_vec(),
    };
    Ok(serde_wasm_bindgen::to_value(&keypair).unwrap())
}

/// Create (Signs) a BBS Signature in the G1 sub-group using a key pair based in
/// G2
///
/// * request: JSON encoded request containing a byte array of messages to be
///   signed and a BLS12-381 key pair
///
/// Returned value is a byte array which is the produced signature (112 bytes)
#[wasm_bindgen(js_name = bbs_bls12381_sign)]
pub async fn bbs_bls12381_sign(
    request: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // Improves error output in JS based console.log() when built with debug
    // feature enabled
    set_panic_hook();

    // Cast the supplied JSON request into a rust struct
    let request: BbsSignRequestDto = request.try_into()?;

    let result = if let Some(messages) = request.messages {
        sign(&BbsSignRequest::<&[u8]> {
            secret_key: &vec_to_u8_sized_array!(
                request.secretKey,
                BBS_BLS12381G1_SECRET_KEY_LENGTH
            ),
            public_key: &vec_to_u8_sized_array!(
                request.publicKey,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH
            ),
            header: request.header.as_ref().map(|m| m.as_slice()),
            messages: Some(
                messages
                    .iter()
                    .map(Vec::as_ref)
                    .collect::<Vec<&[u8]>>()
                    .as_slice(),
            ),
        })
    } else {
        sign(&BbsSignRequest::<&[u8]> {
            secret_key: &vec_to_u8_sized_array!(
                request.secretKey,
                BBS_BLS12381G1_SECRET_KEY_LENGTH
            ),
            public_key: &vec_to_u8_sized_array!(
                request.publicKey,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH
            ),
            header: request.header.as_ref().map(|m| m.as_slice()),
            messages: None,
        })
    };

    match result {
        Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig.to_vec()).unwrap()),
        Err(e) => Err(serde_wasm_bindgen::Error::new(e)),
    }
}

/// Verifies a BBS Signature in the G1 sub-group using a public key based in G2
///
/// * request: JSON encoded request containing a byte array of the signature to
///   verify, the array of byte arrays representing the
/// messages protected by the signature and the BLS12-381 based public key in G2
///
/// Returned value is JSON structure with a boolean value indicating whether the
/// signature was verified and if not any details on the error available
#[wasm_bindgen(js_name = bbs_bls12381_verify)]
pub async fn bbs_bls12381_verify(request: JsValue) -> Result<JsValue, JsValue> {
    // Improves error output in JS based console.log() when built with debug
    // feature enabled
    set_panic_hook();
    // Cast the JSON request into a rust struct
    let res = request.try_into();

    let request: BbsVerifyRequestDto = match res {
        Ok(result) => result,
        Err(e) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: Some(format!("{:?}", e)),
            })
            .unwrap())
        }
    };

    let result = if let Some(messages) = request.messages {
        verify(&BbsVerifyRequest::<&[u8]> {
            public_key: &vec_to_u8_sized_array!(
                request.publicKey,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH
            ),
            header: request.header.as_ref().map(|m| m.as_slice()),
            signature: &vec_to_u8_sized_array!(
                request.signature,
                BBS_BLS12381G1_SIGNATURE_LENGTH
            ),
            messages: Some(
                messages
                    .iter()
                    .map(Vec::as_slice)
                    .collect::<Vec<&[u8]>>()
                    .as_slice(),
            ),
        })
    } else {
        verify(&BbsVerifyRequest::<&[u8]> {
            public_key: &vec_to_u8_sized_array!(
                request.publicKey,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH
            ),
            header: request.header.as_ref().map(|m| m.as_slice()),
            messages: None,
            signature: &vec_to_u8_sized_array!(
                request.signature,
                BBS_BLS12381G1_SIGNATURE_LENGTH
            ),
        })
    };

    match result {
        Ok(result) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: result,
                error: None,
            })
            .unwrap())
        }
        Err(e) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: Some(format!("{:?}", e)),
            })
            .unwrap())
        }
    }
}

/// Derives signature proof of knowledge proof from a supplied BBS Signature in
/// the G1 subgroup
///
/// * request: JSON encoded request containing a byte array of the signature to
///   derive
/// the proof from, an ORDERED array of byte arrays representing the messages
/// protected by the signature, an array indicating which messages to reveal in
/// the derived proof and the BLS12-381 based public key in G2 associated to the
/// original signer of the signature
///
/// {
///     "publicKey": Vec<u8>, // Uint8Array of bytes representing the public key
///     "header": Vec<u8>,
///     "signature": Vec<u8>,
///     "presentationMessage": Vec<u8>,
///     "messages": [{ // Note this array is considered ordered and MUST match
/// the order in which the messages were signed         "value": Vec<u8>, //
/// Uint8Array of raw bytes representing the message         "reveal": boolean
/// // indicates whether or not to reveal the message in the derived proof
///     }]
/// }
///
/// Returned value is a byte array which is the produced proof (variable length)
#[wasm_bindgen(js_name = bbs_bls12381_derive_proof)]
pub async fn bbs_bls12381_derive_proof(
    request: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // Improves error output in JS based console.log() when built with debug
    // feature enabled
    set_panic_hook();

    // Cast the JSON request into a rust struct
    let request: BbsDeriveProofRequestDto = request.try_into()?;

    let result = if let Some(messages) = request.messages {
        proof_gen(&BbsProofGenRequest {
            public_key: &vec_to_u8_sized_array!(
                request.publicKey,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH
            ),
            header: request.header.as_ref().map(|m| m.as_slice()),
            signature: &vec_to_u8_sized_array!(
                request.signature,
                BBS_BLS12381G1_SIGNATURE_LENGTH
            ),
            presentation_message: request
                .presentationMessage
                .as_ref()
                .map(|pm| pm.as_slice()),
            messages: Some(
                messages
                    .iter()
                    .map(|item| BbsProofGenRevealMessageRequest {
                        reveal: item.reveal,
                        value: item.value.as_ref(),
                    })
                    .collect::<Vec<BbsProofGenRevealMessageRequest<_>>>()
                    .as_slice(),
            ),
        })
    } else {
        proof_gen(&BbsProofGenRequest {
            public_key: &vec_to_u8_sized_array!(
                request.publicKey,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH
            ),
            header: request.header.as_ref().map(|m| m.as_slice()),
            signature: &vec_to_u8_sized_array!(
                request.signature,
                BBS_BLS12381G1_SIGNATURE_LENGTH
            ),
            presentation_message: request
                .presentationMessage
                .as_ref()
                .map(|pm| pm.as_slice()),
            messages: None,
        })
    };

    match result {
        Ok(proof) => Ok(serde_wasm_bindgen::to_value(&proof).unwrap()),
        Err(e) => Err(serde_wasm_bindgen::Error::new(e)),
    }
}

/// Verifies a signature proof of knowledge proof
///
/// * request: JSON encoded request TODO
///
/// {
///     "publicKey": Vec<u8>, // Uint8Array of bytes representing the public key
///     "header": Vec<u8>,
///     "proof": Vec<u8>,
///     "presentationMessage": Vec<u8>,
///     "totalMessageCount": usize,
///     "messages": {
///         number: {
///            "value": Vec<u8> // Uint8Array of raw bytes representing the
/// message         }
///     }]
/// }
///
/// Returned value is a byte array which is the produced proof (variable length)
#[wasm_bindgen(js_name = bbs_bls12381_verify_proof)]
pub async fn bbs_bls12381_verify_proof(
    request: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // Improves error output in JS based console.log() when built with debug
    // feature enabled
    set_panic_hook();

    // Cast the JSON request into a rust struct
    let request: BbsVerifyProofRequestDto = request.try_into()?;

    let result = if let Some(messages) = request.messages {
        proof_verify(&BbsProofVerifyRequest {
            public_key: &vec_to_u8_sized_array!(
                request.publicKey,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH
            ),
            header: request.header.as_ref().map(|m| m.as_slice()),
            proof: &request.proof,
            presentation_message: request
                .presentationMessage
                .as_ref()
                .map(|pm| pm.as_slice()),
            total_message_count: request.totalMessageCount,
            messages: Some(
                messages
                    .iter()
                    .map(|(key, value)| {
                        (key.parse::<usize>().unwrap(), value.as_slice())
                    })
                    .collect::<Vec<(usize, &[u8])>>()
                    .as_slice(),
            ),
        })
    } else {
        proof_verify(&BbsProofVerifyRequest {
            public_key: &vec_to_u8_sized_array!(
                request.publicKey,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH
            ),
            header: request.header.as_ref().map(|m| m.as_slice()),
            proof: &request.proof,
            presentation_message: request
                .presentationMessage
                .as_ref()
                .map(|pm| pm.as_slice()),
            total_message_count: request.totalMessageCount,
            messages: None,
        })
    };

    match result {
        Ok(verified) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified, // TODO need to check test cases here
                error: None,
            })
            .unwrap());
        }
        Err(e) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: Some(format!("{:?}", e)),
            })
            .unwrap())
        }
    }
}
