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

import init, { generateBls12381G1KeyPair as _generateBls12381G1KeyPair, generateBls12381G2KeyPair as _generateBls12381G2KeyPair } from "./pairing_crypto_wasm.js";

export const BBS_SIGNATURE_LENGTH = 112;

export const DEFAULT_BLS12381_PRIVATE_KEY_LENGTH = 32;

export const DEFAULT_BLS12381_G1_PUBLIC_KEY_LENGTH = 48;

export const DEFAULT_BLS12381_G2_PUBLIC_KEY_LENGTH = 96;

// Casts a rejected promise to an error rather than a
// simple string result
const throwErrorOnRejectedPromise = async (promise) => {
    try {
        return await promise;
    } catch (ex) {
        throw new Error(ex);
    }
};

export const generateBls12381G1KeyPair = async (seed) => {
    await init();
    var result = await throwErrorOnRejectedPromise(
        generateBls12381G1KeyPair(seed ? seed : null)
    );
    return {
        secretKey: new Uint8Array(result.secretKey),
        publicKey: new Uint8Array(result.publicKey),
    };
};

export const generateBls12381G2KeyPair = async (seed) => {
    await init();
    var result = await throwErrorOnRejectedPromise(
        _generateBls12381G2KeyPair(seed ? seed : null)
    );
    return {
      secretKey: new Uint8Array(result.secretKey),
      publicKey: new Uint8Array(result.publicKey),
    };
};
