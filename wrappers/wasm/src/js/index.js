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

const wasm = require('./wasm_module.js');

// TODO should be able to remove this duplicate definition syntax by using ESM over index.web.js
// in future

const BBS_SIGNATURE_LENGTH = 112;

const DEFAULT_BLS12381_PRIVATE_KEY_LENGTH = 32;

const DEFAULT_BLS12381_G1_PUBLIC_KEY_LENGTH = 48;

const DEFAULT_BLS12381_G2_PUBLIC_KEY_LENGTH = 96;

// Casts a rejected promise to an error rather than a
// simple string result
const throwErrorOnRejectedPromise = async (promise) => {
    try {
        return await promise;
    } catch (ex) {
        if (ex instanceof TypeError && ex.message === 'Reflect.get called on non-object') {
            // Due to serde-wasm-bindgens usage of reflect in serde-rs
            // we are unable to detect `which` element is missing from a request object
            // until that is resolved we cannot provide that level of detail in this particular error case

            // TODO probably should revise this message as its not just thrown when a request is missing an element, can also be thrown when value type of request element in-correct
            throw new TypeError("Request object missing required element");
        }
        throw new Error(ex);
    }
};

let initializedModule;
const initialize = async () => {
    if (!initializedModule) {
        if (typeof wasm.default === "function") {
            initializedModule = await wasm.default();
        }
        else {
            initializedModule = true;
        }
    }
}

const bls12381_GenerateG1KeyPair = async (seed) => {
    await initialize();
    var result = await throwErrorOnRejectedPromise(
        wasm.bls12381_GenerateG1KeyPair(seed ? seed : undefined)
    );
    return {
        secretKey: new Uint8Array(result.secretKey),
        publicKey: new Uint8Array(result.publicKey),
    };
};

const bls12381_GenerateG2KeyPair = async (seed) => {
    await initialize();
    var result = await throwErrorOnRejectedPromise(
        wasm.bls12381_GenerateG2KeyPair(seed ? seed : undefined)
    );
    return {
      secretKey: new Uint8Array(result.secretKey),
      publicKey: new Uint8Array(result.publicKey),
    };
};

const bls12381_Bbs_Sign = async (request) => {
    await initialize();
    return new Uint8Array(await throwErrorOnRejectedPromise(wasm.bls12381_Bbs_SignG1(request)));
};

const bls12381_Bbs_Verify = async (request) => {
    await initialize();
    return await throwErrorOnRejectedPromise(wasm.bls12381_Bbs_VerifyG1(request));
};

const bls12381_Bbs_DeriveProof = async (request) => {
    await initialize();
    return new Uint8Array(await throwErrorOnRejectedPromise(wasm.bls12381_Bbs_DeriveProofG1(request)));
}

const bls12381_Bbs_VerifyProof = async (request) => {
    await initialize();
    return await throwErrorOnRejectedPromise(wasm.bls12381_Bbs_VerifyProofG1(request));
}

module.exports.bls12381 = {
    PRIVATE_KEY_LENGTH: DEFAULT_BLS12381_PRIVATE_KEY_LENGTH,
    G1_PUBLIC_KEY_LENGTH: DEFAULT_BLS12381_G1_PUBLIC_KEY_LENGTH,
    G2_PUBLIC_KEY_LENGTH: DEFAULT_BLS12381_G2_PUBLIC_KEY_LENGTH,

    generateG1KeyPair: bls12381_GenerateG1KeyPair,
    generateG2KeyPair: bls12381_GenerateG2KeyPair,
    bbs: {
        SIGNATURE_LENGTH: BBS_SIGNATURE_LENGTH,
        SIGNER_PUBLIC_KEY_LENGTH: DEFAULT_BLS12381_G2_PUBLIC_KEY_LENGTH,

        generateSignerKeyPair: bls12381_GenerateG2KeyPair,
        sign: bls12381_Bbs_Sign,
        verify: bls12381_Bbs_Verify,
        deriveProof: bls12381_Bbs_DeriveProof,
        verifyProof: bls12381_Bbs_VerifyProof
    }
}