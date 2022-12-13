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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

wasm_impl!(
    KeyGenerationRequestDto,
    ikm: Option<Vec<u8>>,
    keyInfo: Option<Vec<u8>>
);

wasm_impl!(KeyPair, publicKey: Vec<u8>, secretKey: Vec<u8>);

wasm_impl!(
    BlsKeyPopGenRequestDto,
    blsSecretKey: Vec<u8>,
    aud: Vec<u8>,
    dst: Option<Vec<u8>>,
    extra_info: Option<Vec<u8>>
);

wasm_impl!(
    BlsKeyPopVerifyRequestDto,
    blsKeyPop: Vec<u8>,
    blsPublicKey: Vec<u8>,
    aud: Vec<u8>,
    dst: Option<Vec<u8>>,
    extra_info: Option<Vec<u8>>
);

wasm_impl!(
    BbsBoundSignRequestDto,
    secretKey: Vec<u8>,
    publicKey: Vec<u8>,
    blsPublicKey: Vec<u8>,
    header: Option<Vec<u8>>,
    messages: Option<Vec<Vec<u8>>>
);

wasm_impl!(
    BbsBoundVerifyRequestDto,
    publicKey: Vec<u8>,
    blsSecretKey: Vec<u8>,
    header: Option<Vec<u8>>,
    messages: Option<Vec<Vec<u8>>>,
    signature: Vec<u8>
);

wasm_impl!(
    BbsBoundVerifyResponse,
    verified: bool,
    error: Option<String>
);

wasm_impl!(
    BbsBoundDeriveProofRevealMessageRequestDto,
    // consider changing this contract to use an enum instead of 'reveal'
    reveal: bool,
    value: Vec<u8>
);

wasm_impl!(
    BbsBoundDeriveProofRequestDto,
    publicKey: Vec<u8>,
    blsSecretKey: Vec<u8>,
    header: Option<Vec<u8>>,
    messages: Option<Vec<BbsBoundDeriveProofRevealMessageRequestDto>>,
    signature: Vec<u8>,
    presentationHeader: Option<Vec<u8>>,
    verifySignature: Option<bool>
);

wasm_impl!(
    BbsBoundVerifyProofRequestDto,
    publicKey: Vec<u8>,
    header: Option<Vec<u8>>,
    proof: Vec<u8>,
    presentationHeader: Option<Vec<u8>>,
    totalMessageCount: usize,
    messages: Option<HashMap<usize, Vec<u8>>>
);
