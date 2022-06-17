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

wasm_impl!(KeyPair, publicKey: Vec<u8>, secretKey: Option<Vec<u8>>);

wasm_impl!(
    BbsSignRequestDto,
    secretKey: Vec<u8>,
    publicKey: Vec<u8>,
    header: Option<Vec<u8>>,
    messages: Option<Vec<Vec<u8>>>
);

wasm_impl!(
    BbsVerifyRequestDto,
    publicKey: Vec<u8>,
    header: Option<Vec<u8>>,
    messages: Option<Vec<Vec<u8>>>,
    signature: Vec<u8>
);
wasm_impl!(BbsVerifyResponse, verified: bool, error: Option<String>);

wasm_impl!(
    BbsDeriveProofRevealMessageRequestDto,
    // consider changing this contract to use an enum instead of 'reveal'
    reveal: bool,
    value: Vec<u8>
);

wasm_impl!(
    BbsDeriveProofRequestDto,
    publicKey: Vec<u8>,
    header: Option<Vec<u8>>,
    messages: Option<Vec<BbsDeriveProofRevealMessageRequestDto>>,
    signature: Vec<u8>,
    presentationMessage: Option<Vec<u8>>
);

wasm_impl!(
    BbsVerifyProofRequestDto,
    publicKey: Vec<u8>,
    header: Option<Vec<u8>>,
    proof: Vec<u8>,
    presentationMessage: Option<Vec<u8>>,
    totalMessageCount: usize,
    messages: Option<HashMap<String, Vec<u8>>> /* This has to be HashMap due
                                                * to
                                                * supported types in
                                                * wasm_bindgen */
);
