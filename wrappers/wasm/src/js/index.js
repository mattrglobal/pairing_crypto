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

const DEFAULT_BLS12381_BBS_SIGNATURE_LENGTH = 112;

const DEFAULT_BLS12381_PRIVATE_KEY_LENGTH = 32;

const DEFAULT_BLS12381_PUBLIC_KEY_LENGTH = 96;

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

const bbs_bls12_381_generate_key_pair = async (request) => {
    await initialize();
    var result = await throwErrorOnRejectedPromise(
        wasm.bbs_bls12_381_generate_key_pair(request ?? {})
    );
    return {
        secretKey: new Uint8Array(result.secretKey),
        publicKey: new Uint8Array(result.publicKey),
    };
};

const bbs_bls12_381_sha_256_sign = async (request) => {
    await initialize();
    return new Uint8Array(await throwErrorOnRejectedPromise(wasm.bbs_bls12_381_sha_256_sign(request)));
};

const bbs_bls12_381_sha_256_verify = async (request) => {
    await initialize();
    return await throwErrorOnRejectedPromise(wasm.bbs_bls12_381_sha_256_verify(request));
};

const bbs_bls12_381_sha_256_proof_gen = async (request) => {
    await initialize();
    return new Uint8Array(await throwErrorOnRejectedPromise(wasm.bbs_bls12_381_sha_256_proof_gen(request)));
}

const bbs_bls12_381_sha_256_proof_verify = async (request) => {
    await initialize();
    return await throwErrorOnRejectedPromise(wasm.bbs_bls12_381_sha_256_proof_verify(request));
}

const bbs_bls12_381_shake_256_sign = async (request) => {
    await initialize();
    return new Uint8Array(await throwErrorOnRejectedPromise(wasm.bbs_bls12_381_shake_256_sign(request)));
};

const bbs_bls12_381_shake_256_verify = async (request) => {
    await initialize();
    return await throwErrorOnRejectedPromise(wasm.bbs_bls12_381_shake_256_verify(request));
};

const bbs_bls12_381_shake_256_proof_gen = async (request) => {
    await initialize();
    return new Uint8Array(await throwErrorOnRejectedPromise(wasm.bbs_bls12_381_shake_256_proof_gen(request)));
}

const bbs_bls12_381_shake_256_proof_verify = async (request) => {
    await initialize();
    return await throwErrorOnRejectedPromise(wasm.bbs_bls12_381_shake_256_proof_verify(request));
}

const convertToRevealMessageArray = (messages, revealedIndicies) => {
    let revealMessages = [];
    let i = 0;
    messages.forEach((element) => {
        if (revealedIndicies.includes(i)) {
            revealMessages.push({ value: element, reveal: true });
        } else {
            revealMessages.push({ value: element, reveal: false });
        }
        i++;
    })
    return revealMessages;
}

const convertRevealMessageArrayToRevealMap = (messages) => {
    return messages.reduce(
        (map, item, index) => {
            if (item.reveal) {
                map = {
                    ...map,
                    [index]: item.value,
                };
            }
            return map;
        },
        {}
    );
}

module.exports.bbs = {
    bls12381_sha256: {
        PRIVATE_KEY_LENGTH: DEFAULT_BLS12381_PRIVATE_KEY_LENGTH,
        PUBLIC_KEY_LENGTH: DEFAULT_BLS12381_PUBLIC_KEY_LENGTH,
        SIGNATURE_LENGTH: DEFAULT_BLS12381_BBS_SIGNATURE_LENGTH,

        generateKeyPair: bbs_bls12_381_generate_key_pair,
        sign: bbs_bls12_381_sha_256_sign,
        verify: bbs_bls12_381_sha_256_verify,
        deriveProof: bbs_bls12_381_sha_256_proof_gen,
        verifyProof: bbs_bls12_381_sha_256_proof_verify
    },
    bls12381_shake256: {
        PRIVATE_KEY_LENGTH: DEFAULT_BLS12381_PRIVATE_KEY_LENGTH,
        PUBLIC_KEY_LENGTH: DEFAULT_BLS12381_PUBLIC_KEY_LENGTH,
        SIGNATURE_LENGTH: DEFAULT_BLS12381_BBS_SIGNATURE_LENGTH,

        generateKeyPair: bbs_bls12_381_generate_key_pair,
        sign: bbs_bls12_381_shake_256_sign,
        verify: bbs_bls12_381_shake_256_verify,
        deriveProof: bbs_bls12_381_shake_256_proof_gen,
        verifyProof: bbs_bls12_381_shake_256_proof_verify
    }
}

module.exports.utilities = {
    convertToRevealMessageArray,
    convertRevealMessageArrayToRevealMap
}