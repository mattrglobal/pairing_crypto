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

use super::dtos::*;
use crate::utils::*;
use core::convert::{TryFrom, TryInto};
use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::{
            KeyPair as Bls12381BbsKeyPair,
            PublicKey as Bls12381BbsPublicKey,
            BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
            BBS_BLS12381G1_SECRET_KEY_LENGTH,
            BBS_BLS12381G1_SIGNATURE_LENGTH,
        },
        bls12_381_g1_sha_256::{
            proof_gen as bls12_381_sha_256_proof_gen,
            proof_verify as bls12_381_sha_256_proof_verify,
            sign as bls12_381_sha_256_sign,
            verify as bls12_381_sha_256_verify,
        },
        bls12_381_g1_shake_256::{
            proof_gen as bls12_381_shake_256_proof_gen,
            proof_verify as bls12_381_shake_256_proof_verify,
            sign as bls12_381_shake_256_sign,
            verify as bls12_381_shake_256_verify,
        },
    },
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
    BbsVerifyRequest,
};
use pairing_crypto::Error;
use wasm_bindgen::prelude::*;

/// Generate a BBS key pair on BLS 12-381 curve.
///
/// * request: JSON encoded request optionally containing
///             - IKM: Input Key Material (if not supplied a random value will
///               be generated via RNG)
///             - key_info: Key information
///
/// Returned value is a byte array which is the concatenation of first
/// the private key (32 bytes) followed by the public key (96) bytes.
#[wasm_bindgen(js_name = bbs_bls12_381_generate_key_pair)]
pub async fn bbs_bls12_381_generate_key_pair(
    request: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // Improves error output in JS based console.log() when built with
    // debug feature enabled
    set_panic_hook();

    // Cast the supplied JSON request into a rust struct
    let request: KeyGenerationRequestDto = request.try_into()?;

    let ikm = request.ikm.unwrap_or(Vec::new());
    let key_info = request.keyInfo.unwrap_or(Vec::new());

    // // Derive secret key from supplied IKM and key information
    // metadata.
    let key_pair = Bls12381BbsKeyPair::new(&ikm, &key_info).ok_or(
        serde_wasm_bindgen::Error::new(
            "unexpected error, failed to generate keys.",
        ),
    )?;

    // Construct the JS DTO of the key pair to return
    let keypair = KeyPair {
        secretKey: key_pair.secret_key.to_bytes().to_vec(),
        publicKey: key_pair.public_key.to_octets().to_vec(),
    };
    serde_wasm_bindgen::to_value(&keypair)
}


/// Generate a key pair in uncompressed form
#[wasm_bindgen(js_name = bbs_bls12_381_generate_key_pair_uncompressed)]
pub async fn bbs_bls12_381_generate_key_pair_uncompressed(
    request: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // Improves error output in JS based console.log() when built with
    // debug feature enabled
    set_panic_hook();

    // Cast the supplied JSON request into a rust struct
    let request: KeyGenerationRequestDto = request.try_into()?;

    let ikm = request.ikm.unwrap_or(Vec::new());
    let key_info = request.keyInfo.unwrap_or(Vec::new());

    // // Derive secret key from supplied IKM and key information
    // metadata.
    let key_pair = Bls12381BbsKeyPair::new(&ikm, &key_info).ok_or(
        serde_wasm_bindgen::Error::new(
            "unexpected error, failed to generate keys.",
        ),
    )?;

    // Construct the JS DTO of the key pair to return
    let keypair = KeyPair {
        secretKey: key_pair.secret_key.to_bytes().to_vec(),
        publicKey: key_pair.public_key.to_octets_uncompressed().to_vec(),
    };
    serde_wasm_bindgen::to_value(&keypair)
}



/// Convert the public key representation from compressed to uncompressed
#[wasm_bindgen(js_name = bbs_bls12_381_compressed_to_uncompressed_public_key)]
pub async fn bbs_bls12_381_compressed_to_uncompressed_public_key(
    request: Vec<u8>
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // debug feature enabled
    set_panic_hook();

    match Bls12381BbsPublicKey::compressed_to_uncompressed(&request) {
        Ok(bytes) => serde_wasm_bindgen::to_value(&bytes.to_vec()),
        Err(e) if e == Error::BadEncoding => Err(serde_wasm_bindgen::Error::new(
            "unexpected error, input public key is incorrectly encoded."
        )),
        Err(_) => Err(serde_wasm_bindgen::Error::new(
            "unexpected error, failed to map public key from compressed to uncompressed form."
        )),
    }
}

/// Convert the public key representation from uncompressed to compressed
#[wasm_bindgen(js_name = bbs_bls12_381_uncompressed_to_compressed_public_key)]
pub async fn bbs_bls12_381_uncompressed_to_compressed_public_key(
    request: Vec<u8>
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    // debug feature enabled
    set_panic_hook();

    match Bls12381BbsPublicKey::uncompressed_to_compressed(&request) {
        Ok(bytes) => serde_wasm_bindgen::to_value(&bytes.to_vec()),
        Err(e) if e == Error::BadEncoding => Err(serde_wasm_bindgen::Error::new(
            "unexpected error, input public key is incorrectly encoded."
        )),
        Err(_) => Err(serde_wasm_bindgen::Error::new(
            "unexpected error, failed to map public key from uncompressed to compressed form."
        )),
    }
}

macro_rules! bbs_wrapper_api_generator {
    (
        $sign_wrapper_fn:ident,
        $sign_lib_fn:ident,
        $verify_wrapper_fn:ident,
        $verify_lib_fn:ident,
        $proof_gen_wrapper_fn:ident,
        $proof_gen_lib_fn:ident,
        $proof_verify_wrapper_fn:ident,
        $proof_verify_lib_fn:ident,
    ) => {
        /// Create (Signs) a BBS Signature in the G1 sub-group using a key pair
        /// based in G2
        ///
        /// * request: JSON encoded request containing a byte array of messages
        ///   to be signed and a BLS12-381 key pair
        ///
        /// Returned value is a byte array which is the produced signature (112
        /// bytes)
        #[wasm_bindgen(js_name = $sign_wrapper_fn)]
        pub async fn $sign_wrapper_fn(
            request: JsValue,
        ) -> Result<JsValue, serde_wasm_bindgen::Error> {
            // Improves error output in JS based console.log() when built with
            // debug feature enabled
            set_panic_hook();

            // Cast the supplied JSON request into a rust struct
            let request: BbsSignRequestDto = request.try_into()?;

            let api_request = BbsSignRequest::<&[u8]> {
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
            };

            let result = if let Some(messages) = request.messages {
                $sign_lib_fn(&BbsSignRequest::<&[u8]> {
                    messages: Some(
                        messages
                            .iter()
                            .map(Vec::as_ref)
                            .collect::<Vec<&[u8]>>()
                            .as_slice(),
                    ),
                    ..api_request
                })
            } else {
                $sign_lib_fn(&api_request)
            };

            match result {
                Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig.to_vec())?),
                Err(e) => Err(serde_wasm_bindgen::Error::new(e)),
            }
        }

        /// Verifies a BBS Signature in the G1 sub-group using a public key
        /// based in G2
        ///
        /// * request: JSON encoded request containing a byte array of the
        ///   signature to verify, the array of byte arrays representing the
        /// messages protected by the signature and the BLS12-381 based public
        /// key in G2
        ///
        /// Returned value is JSON structure with a boolean value indicating
        /// whether the signature was verified and if not any details on the
        /// error available
        #[wasm_bindgen(js_name = $verify_wrapper_fn)]
        pub async fn $verify_wrapper_fn(
            request: JsValue,
        ) -> Result<JsValue, JsValue> {
            // Improves error output in JS based console.log() when built with
            // debug feature enabled
            set_panic_hook();
            // Cast the JSON request into a rust struct
            let res = request.try_into();

            let request: BbsVerifyRequestDto = match res {
                Ok(result) => result,
                Err(e) => {
                    return Ok(serde_wasm_bindgen::to_value(
                        &BbsVerifyResponse {
                            verified: false,
                            error: Some(format!("{:?}", e)),
                        },
                    )?)
                }
            };

            let api_request = BbsVerifyRequest::<&[u8]> {
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
            };

            let result = if let Some(messages) = request.messages {
                $verify_lib_fn(&BbsVerifyRequest::<&[u8]> {
                    messages: Some(
                        messages
                            .iter()
                            .map(Vec::as_slice)
                            .collect::<Vec<&[u8]>>()
                            .as_slice(),
                    ),
                    ..api_request
                })
            } else {
                $verify_lib_fn(&api_request)
            };

            match result {
                Ok(result) => {
                    return Ok(serde_wasm_bindgen::to_value(
                        &BbsVerifyResponse {
                            verified: result,
                            error: None,
                        },
                    )?)
                }
                Err(e) => {
                    return Ok(serde_wasm_bindgen::to_value(
                        &BbsVerifyResponse {
                            verified: false,
                            error: Some(format!("{:?}", e)),
                        },
                    )?)
                }
            }
        }

        /// Derives signature proof of knowledge proof from a supplied BBS
        /// Signature in the G1 subgroup
        ///
        /// * request: JSON encoded request containing a byte array of the
        ///   signature to derive
        /// the proof from, an ORDERED array of byte arrays representing the
        /// messages protected by the signature, an array indicating which
        /// messages to reveal in the derived proof and the BLS12-381 based
        /// public key in G2 associated to the original signer of the signature
        ///
        /// {
        ///     "publicKey": Vec<u8>, // Uint8Array of bytes representing the
        /// public key     "header": Vec<u8>,
        ///     "signature": Vec<u8>,
        ///     "presentationHeader": Vec<u8>,
        ///     "messages": [{ // Note this array is considered ordered and MUST
        /// match the order in which the messages were signed         "value":
        /// Vec<u8>, // Uint8Array of raw bytes representing the message
        /// "reveal": boolean // indicates whether or not to reveal the message
        /// in the derived proof     }]
        /// }
        ///
        /// Returned value is a byte array which is the produced proof (variable
        /// length)
        #[wasm_bindgen(js_name = $proof_gen_wrapper_fn)]
        pub async fn $proof_gen_wrapper_fn(
            request: JsValue,
        ) -> Result<JsValue, serde_wasm_bindgen::Error> {
            // Improves error output in JS based console.log() when built with
            // debug feature enabled
            set_panic_hook();

            // Cast the JSON request into a rust struct
            let request: BbsDeriveProofRequestDto = request.try_into()?;

            let api_request = BbsProofGenRequest {
                public_key: &vec_to_u8_sized_array!(
                    request.publicKey,
                    BBS_BLS12381G1_PUBLIC_KEY_LENGTH
                ),
                header: request.header.as_ref().map(|m| m.as_slice()),
                signature: &vec_to_u8_sized_array!(
                    request.signature,
                    BBS_BLS12381G1_SIGNATURE_LENGTH
                ),
                presentation_header: request
                    .presentationHeader
                    .as_ref()
                    .map(|pm| pm.as_slice()),
                verify_signature: request.verifySignature,
                messages: None,
            };

            let result = if let Some(messages) = request.messages {
                $proof_gen_lib_fn(&BbsProofGenRequest {
                    messages: Some(
                        messages
                            .iter()
                            .map(|item| BbsProofGenRevealMessageRequest {
                                reveal: item.reveal,
                                value: item.value.as_ref(),
                            })
                            .collect::<Vec<BbsProofGenRevealMessageRequest<_>>>(
                            )
                            .as_slice(),
                    ),
                    ..api_request
                })
            } else {
                $proof_gen_lib_fn(&api_request)
            };

            match result {
                Ok(proof) => Ok(serde_wasm_bindgen::to_value(&proof)?),
                Err(e) => Err(serde_wasm_bindgen::Error::new(e)),
            }
        }

        /// Verifies a signature proof of knowledge proof
        ///
        /// * request: JSON encoded request TODO
        ///
        /// {
        ///     "publicKey": Vec<u8>, // Uint8Array of bytes representing the
        /// public key     "header": Vec<u8>,
        ///     "proof": Vec<u8>,
        ///     "presentationHeader": Vec<u8>,
        ///     "messages": {
        ///         number: {
        ///            "value": Vec<u8> // Uint8Array of raw bytes representing
        /// the message         }
        ///     }]
        /// }
        ///
        /// Returned value is a byte array which is the produced proof (variable
        /// length)
        #[wasm_bindgen(js_name = $proof_verify_wrapper_fn)]
        pub async fn $proof_verify_wrapper_fn(
            request: JsValue,
        ) -> Result<JsValue, serde_wasm_bindgen::Error> {
            // Improves error output in JS based console.log() when built with
            // debug feature enabled
            set_panic_hook();

            // Cast the JSON request into a rust struct
            let request: BbsVerifyProofRequestDto = request.try_into()?;

            let api_request = BbsProofVerifyRequest {
                public_key: &vec_to_u8_sized_array!(
                    request.publicKey,
                    BBS_BLS12381G1_PUBLIC_KEY_LENGTH
                ),
                header: request.header.as_ref().map(|m| m.as_slice()),
                proof: &request.proof,
                presentation_header: request
                    .presentationHeader
                    .as_ref()
                    .map(|pm| pm.as_slice()),
                messages: None,
            };

            let result = if let Some(messages) = request.messages {
                $proof_verify_lib_fn(&BbsProofVerifyRequest {
                    messages: Some(
                        messages
                            .iter()
                            .map(|(key, value)| match key.parse::<usize>() {
                                Ok(k) => Ok((k, value.as_slice())),
                                Err(e) => {
                                    Err(serde_wasm_bindgen::Error::new(e))
                                }
                            })
                            .collect::<Result<Vec<(usize, &[u8])>, _>>()?
                            .as_slice(),
                    ),
                    ..api_request
                })
            } else {
                $proof_verify_lib_fn(&api_request)
            };

            match result {
                Ok(verified) => {
                    return serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                        verified,
                        error: None,
                    });
                }
                Err(e) => {
                    return serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                        verified: false,
                        error: Some(format!("{:?}", e)),
                    })
                }
            }
        }
    };
}

bbs_wrapper_api_generator!(
    bbs_bls12_381_sha_256_sign,
    bls12_381_sha_256_sign,
    bbs_bls12_381_sha_256_verify,
    bls12_381_sha_256_verify,
    bbs_bls12_381_sha_256_proof_gen,
    bls12_381_sha_256_proof_gen,
    bbs_bls12_381_sha_256_proof_verify,
    bls12_381_sha_256_proof_verify,
);

bbs_wrapper_api_generator!(
    bbs_bls12_381_shake_256_sign,
    bls12_381_shake_256_sign,
    bbs_bls12_381_shake_256_verify,
    bls12_381_shake_256_verify,
    bbs_bls12_381_shake_256_proof_gen,
    bls12_381_shake_256_proof_gen,
    bbs_bls12_381_shake_256_proof_verify,
    bls12_381_shake_256_proof_verify,
);
