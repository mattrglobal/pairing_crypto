'use strict';
/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const { randomBytes } = require('@stablelib/random')
const wasm = require('./pairing_crypto_wasm.js');

// TODO should be able to remove this duplicate definition syntax by using ESM over index.web.js
// in future

module.exports.BBS_SIGNATURE_LENGTH = 112;

module.exports.DEFAULT_BLS12381_PRIVATE_KEY_LENGTH = 32;

module.exports.DEFAULT_BLS12381_G1_PUBLIC_KEY_LENGTH = 48;

module.exports.DEFAULT_BLS12381_G2_PUBLIC_KEY_LENGTH = 96;

// Casts a rejected promise to an error rather than a
// simple string result
const throwErrorOnRejectedPromise = async (promise) => {
    try {
        return await promise;
    } catch (ex) {
        throw new Error(ex);
    }
};

let initializedModule;
const initialize = async () => {
    if (!initializedModule) {
        initializedModule = await wasm.default();
    }
}

module.exports.bls12381GenerateG1KeyPair = async (seed) => {
    await initialize();
    var result = await throwErrorOnRejectedPromise(
        wasm.bls12381GenerateG1KeyPair(seed ? seed : await randomBytes(32))
    );
    return {
        secretKey: new Uint8Array(result.secretKey),
        publicKey: new Uint8Array(result.publicKey),
    };
};

module.exports.bls12381GenerateG2KeyPair = async (seed) => {
    await initialize();
    var result = await throwErrorOnRejectedPromise(
        wasm.bls12381GenerateG2KeyPair(seed ? seed : await randomBytes(32))
    );
    return {
      secretKey: new Uint8Array(result.secretKey),
      publicKey: new Uint8Array(result.publicKey),
    };
};
