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

use crate::utils::set_panic_hook;

use super::dtos::*;
use core::convert::{TryFrom, TryInto};
use pairing_crypto::{
    bbs::ciphersuites::bls12_381::{
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
        BBS_BLS12381G1_SECRET_KEY_LENGTH,
        BBS_BLS12381G1_SIGNATURE_LENGTH,
    },
    bbs_bound::{
        ciphersuites::bls12_381_bbs_g1_bls_sig_g2_sha_256::{
            bls_key_pop as bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_gen,
            bls_key_pop_verify as bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_verify,
            proof_gen as bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen,
            proof_verify as bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify,
            sign as bls12_381_bbs_g1_bls_sig_g2_sha_256_sign,
            verify as bls12_381_bbs_g1_bls_sig_g2_sha_256_verify,
            BbsKeyPair,
        },
        BbsBoundProofGenRequest,
        BbsBoundProofGenRevealMessageRequest,
        BbsBoundProofVerifyRequest,
        BbsBoundSignRequest,
        BbsBoundVerifyRequest,
        BlsKeyPopGenRequest,
        BlsKeyPopVerifyRequest,
    },
    bls::ciphersuites::bls12_381::{
        KeyPair as BlsSigBls12381G2KeyPair,
        BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH,
        BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH,
        BLS_SIG_BLS12381G2_SIGNATURE_LENGTH,
    },
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
/// Returned value is a byte array which is the concatenation of first
/// the private key (32 bytes) followed by the public key (96) bytes.
#[wasm_bindgen(js_name = bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bbs_key_pair)]
pub async fn bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bbs_key_pair(
    request: JsValue,
) -> Result<JsValue, JsValue> {
    // Improves error output in JS based console.log() when built with
    // debug feature enabled
    set_panic_hook();

    // Cast the supplied JSON request into a rust struct
    let request: KeyGenerationRequestDto = request.try_into()?;

    // // Derive secret key from supplied IKM and key information
    // metadata.
    let key_pair = match request.ikm {
        Some(ikm) => {
            BbsKeyPair::new(&ikm, request.keyInfo.as_ref().map(Vec::as_ref))
                .unwrap()
        }
        None => BbsKeyPair::random(
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

/// Generate a BBS key pair on BLS 12-381 curve.
///
/// * request: JSON encoded request optionally containing
///             - IKM: Input Key Material (if not supplied a random value will
///               be generated via RNG)
///             - key_info: Key information
///
/// Returned value is a byte array which is the concatenation of first
/// the private key (32 bytes) followed by the public key (96) bytes.
#[wasm_bindgen(js_name = bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bls_key_pair)]
pub async fn bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bls_key_pair(
    request: JsValue,
) -> Result<JsValue, JsValue> {
    // Improves error output in JS based console.log() when built with
    // debug feature enabled
    set_panic_hook();

    // Cast the supplied JSON request into a rust struct
    let request: KeyGenerationRequestDto = request.try_into()?;

    // // Derive secret key from supplied IKM and key information
    // metadata.
    let key_pair = match request.ikm {
        Some(ikm) => BlsSigBls12381G2KeyPair::new(
            &ikm,
            request.keyInfo.as_ref().map(Vec::as_ref),
        )
        .unwrap(),
        None => BlsSigBls12381G2KeyPair::random(
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

macro_rules! bbs_bound_wrapper_api_generator {
    (
        $key_pop_gen_wrapper_fn:ident,
        $key_pop_gen_lib_fn:ident,
        $key_pop_verify_wrapper_fn:ident,
        $key_pop_verify_lib_fn:ident,
        $sign_wrapper_fn:ident,
        $sign_lib_fn:ident,
        $verify_wrapper_fn:ident,
        $verify_lib_fn:ident,
        $proof_gen_wrapper_fn:ident,
        $proof_gen_lib_fn:ident,
        $proof_verify_wrapper_fn:ident,
        $proof_verify_lib_fn:ident
    ) => {

        /// Create a BLS proof of posession for a BLS signature secret key
        ///
        /// * request: JSON encoded request containing a byte array of
        ///             information to construct a BLS key-pop-message
        ///
        /// Returned value is a byte array which is the produced PoP (112
        /// bytes)
        #[wasm_bindgen(js_name = $key_pop_gen_wrapper_fn)]
        pub async fn $key_pop_gen_wrapper_fn(
            request: JsValue,
        ) -> Result<JsValue, serde_wasm_bindgen::Error> {
            // Improves error output in JS based console.log() when built with
            // debug feature enabled
            set_panic_hook();

            // Cast the supplied JSON request into a rust struct
            let request: BlsKeyPopGenRequestDto = request.try_into()?;

            let api_request = BlsKeyPopGenRequest {
                bls_secret_key: &vec_to_u8_sized_array!(
                    request.blsSecretKey,
                    BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH
                ),
                aud: &request.aud,
                dst: request.dst.as_ref().map(|m| m.as_slice()),
                extra_info: request.extra_info.as_ref().map(|m| m.as_slice()),
            };

            match $key_pop_gen_lib_fn(&api_request) {
                Ok(pop) => {
                    Ok(serde_wasm_bindgen::to_value(&pop.to_vec()).unwrap())
                }
                Err(e) => Err(serde_wasm_bindgen::Error::new(e)),
            }
        }

        /// Verify a BLS proof of posession for a BLS signature secret key
        ///
        /// * request: JSON encoded request containing a byte array of
        ///            a BLS key-pop-message
        ///
        /// Returned value is JSON structure with a boolean value indicating
        /// whether the proof of posession was verified and if not any
        /// details on the error available
        #[wasm_bindgen(js_name = $key_pop_verify_wrapper_fn)]
        pub async fn $key_pop_verify_wrapper_fn(
            request: JsValue,
        ) -> Result<JsValue, serde_wasm_bindgen::Error> {
            // Improves error output in JS based console.log() when built with
            // debug feature enabled
            set_panic_hook();

            // Cast the supplied JSON request into a rust struct
            let request: BlsKeyPopVerifyRequestDto = request.try_into()?;

            let api_request = BlsKeyPopVerifyRequest {
                bls_key_pop: &vec_to_u8_sized_array!(
                    request.blsKeyPop,
                    BLS_SIG_BLS12381G2_SIGNATURE_LENGTH
                ),
                bls_public_key: &vec_to_u8_sized_array!(
                    request.blsPublicKey,
                    BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH
                ),
                aud: &request.aud,
                dst: request.dst.as_ref().map(|m| m.as_slice()),
                extra_info: request.extra_info.as_ref().map(|m| m.as_slice()),
            };

            match $key_pop_verify_lib_fn(&api_request) {
                Ok(result) => {
                    return Ok(serde_wasm_bindgen::to_value(
                        &BbsBoundVerifyResponse {
                            verified: result,
                            error: None,
                        },
                    )
                    .unwrap())
                }
                Err(e) => {
                    return Ok(serde_wasm_bindgen::to_value(
                        &BbsBoundVerifyResponse {
                            verified: false,
                            error: Some(format!("{:?}", e)),
                        },
                    )
                    .unwrap())
                }
            }
        }

        /// Create (Signs) a BBS bound Signature in the G1 sub-group using a key
        /// pair based in G2
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
            let request: BbsBoundSignRequestDto = request.try_into()?;

            let api_request = BbsBoundSignRequest::<&[u8]> {
                secret_key: &vec_to_u8_sized_array!(
                    request.secretKey,
                    BBS_BLS12381G1_SECRET_KEY_LENGTH
                ),
                public_key: &vec_to_u8_sized_array!(
                    request.publicKey,
                    BBS_BLS12381G1_PUBLIC_KEY_LENGTH
                ),
                bls_public_key: &vec_to_u8_sized_array!(
                    request.blsPublicKey,
                    BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH
                ),
                header: request.header.as_ref().map(|m| m.as_slice()),
                messages: None,
            };

            let result = if let Some(messages) = request.messages {
                $sign_lib_fn(&BbsBoundSignRequest::<&[u8]> {
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
                Ok(sig) => {
                    Ok(serde_wasm_bindgen::to_value(&sig.to_vec()).unwrap())
                }
                Err(e) => Err(serde_wasm_bindgen::Error::new(e)),
            }
        }

        /// Verifies a BBS bound Signature in the G1 sub-group using a public
        /// key based in G2
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

            let request: BbsBoundVerifyRequestDto = match res {
                Ok(result) => result,
                Err(e) => {
                    return Ok(serde_wasm_bindgen::to_value(
                        &BbsBoundVerifyResponse {
                            verified: false,
                            error: Some(format!("{:?}", e)),
                        },
                    )
                    .unwrap())
                }
            };

            let api_request = BbsBoundVerifyRequest::<&[u8]> {
                public_key: &vec_to_u8_sized_array!(
                    request.publicKey,
                    BBS_BLS12381G1_PUBLIC_KEY_LENGTH
                ),
                bls_secret_key: &vec_to_u8_sized_array!(
                    request.blsSecretKey,
                    BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH
                ),
                header: request.header.as_ref().map(|m| m.as_slice()),
                messages: None,
                signature: &vec_to_u8_sized_array!(
                    request.signature,
                    BBS_BLS12381G1_SIGNATURE_LENGTH
                ),
            };

            let result = if let Some(messages) = request.messages {
                $verify_lib_fn(&BbsBoundVerifyRequest::<&[u8]> {
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
                        &BbsBoundVerifyResponse {
                            verified: result,
                            error: None,
                        },
                    )
                    .unwrap())
                }
                Err(e) => {
                    return Ok(serde_wasm_bindgen::to_value(
                        &BbsBoundVerifyResponse {
                            verified: false,
                            error: Some(format!("{:?}", e)),
                        },
                    )
                    .unwrap())
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
            let request: BbsBoundDeriveProofRequestDto = request.try_into()?;

            let api_request = BbsBoundProofGenRequest {
                public_key: &vec_to_u8_sized_array!(
                    request.publicKey,
                    BBS_BLS12381G1_PUBLIC_KEY_LENGTH
                ),
                bls_secret_key: &vec_to_u8_sized_array!(
                    request.blsSecretKey,
                    BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH
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
                $proof_gen_lib_fn(&BbsBoundProofGenRequest {
                    messages: Some(
                        messages
                            .iter()
                            .map(|item| BbsBoundProofGenRevealMessageRequest {
                                reveal: item.reveal,
                                value: item.value.as_ref(),
                            })
                            .collect::<Vec<BbsBoundProofGenRevealMessageRequest<_>>>(
                            )
                            .as_slice(),
                    ),
                    ..api_request
                })
            } else {
                $proof_gen_lib_fn(&api_request)
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
        ///     "publicKey": Vec<u8>, // Uint8Array of bytes representing the
        /// public key     "header": Vec<u8>,
        ///     "proof": Vec<u8>,
        ///     "presentationHeader": Vec<u8>,
        ///     "totalMessageCount": usize,
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
            let request: BbsBoundVerifyProofRequestDto = request.try_into()?;

            let api_request = BbsBoundProofVerifyRequest {
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
                total_message_count: request.totalMessageCount,
                messages: None,
            };

            let result = if let Some(messages) = request.messages {
                $proof_verify_lib_fn(&BbsBoundProofVerifyRequest {
                    messages: Some(
                        messages
                            .iter()
                            .map(|(key, value)| {
                                (
                                    key.parse::<usize>().unwrap(),
                                    value.as_slice(),
                                )
                            })
                            .collect::<Vec<(usize, &[u8])>>()
                            .as_slice(),
                    ),
                    ..api_request
                })
            } else {
                $proof_verify_lib_fn(&api_request)
            };

            match result {
                Ok(verified) => {
                    return Ok(serde_wasm_bindgen::to_value(
                        &BbsBoundVerifyResponse {
                            verified,
                            error: None,
                        },
                    )
                    .unwrap());
                }
                Err(e) => {
                    return Ok(serde_wasm_bindgen::to_value(
                        &BbsBoundVerifyResponse {
                            verified: false,
                            error: Some(format!("{:?}", e)),
                        },
                    )
                    .unwrap())
                }
            }
        }
    };
}

bbs_bound_wrapper_api_generator!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_gen,
    bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_gen,
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_verify,
    bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_verify,
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign,
    bls12_381_bbs_g1_bls_sig_g2_sha_256_sign,
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify,
    bls12_381_bbs_g1_bls_sig_g2_sha_256_verify,
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen,
    bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen,
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify,
    bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify
);
