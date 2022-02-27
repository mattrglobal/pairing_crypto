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

const bls12381_generate_g1_key = async (seed) => {
    await initialize();
    var result = await throwErrorOnRejectedPromise(
        wasm.bls12381_generate_g1_key(seed ? seed : undefined)
    );
    return {
        secretKey: new Uint8Array(result.secretKey),
        publicKey: new Uint8Array(result.publicKey),
    };
};

const bls12381_generate_g2_key = async (seed) => {
    await initialize();
    var result = await throwErrorOnRejectedPromise(
        wasm.bls12381_generate_g2_key(seed ? seed : undefined)
    );
    return {
      secretKey: new Uint8Array(result.secretKey),
      publicKey: new Uint8Array(result.publicKey),
    };
};

const bls12381_bbs_sign = async (request) => {
    await initialize();
    return new Uint8Array(await throwErrorOnRejectedPromise(wasm.bls12381_bbs_sign(request)));
};

const bls12381_bbs_verify = async (request) => {
    await initialize();
    return await throwErrorOnRejectedPromise(wasm.bls12381_bbs_verify(request));
};

const bls12381_bbs_derive_proof = async (request) => {
    await initialize();
    return new Uint8Array(await throwErrorOnRejectedPromise(wasm.bls12381_bbs_derive_proof(request)));
}

const bls12381_bbs_verify_proof = async (request) => {
    await initialize();
    return await throwErrorOnRejectedPromise(wasm.bls12381_bbs_verify_proof(request));
}

const convertToRevealMessageArray = (messages, revealedIndicies) => {
    let revealMessages= [];
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

module.exports.bls12381 = {
    PRIVATE_KEY_LENGTH: DEFAULT_BLS12381_PRIVATE_KEY_LENGTH,
    G1_PUBLIC_KEY_LENGTH: DEFAULT_BLS12381_G1_PUBLIC_KEY_LENGTH,
    G2_PUBLIC_KEY_LENGTH: DEFAULT_BLS12381_G2_PUBLIC_KEY_LENGTH,

    generateG1KeyPair: bls12381_generate_g1_key,
    generateG2KeyPair: bls12381_generate_g2_key,
    bbs: {
        SIGNATURE_LENGTH: BBS_SIGNATURE_LENGTH,
        SIGNER_PUBLIC_KEY_LENGTH: DEFAULT_BLS12381_G2_PUBLIC_KEY_LENGTH,

        generateSignerKeyPair: bls12381_generate_g2_key,
        sign: bls12381_bbs_sign,
        verify: bls12381_bbs_verify,
        deriveProof: bls12381_bbs_derive_proof,
        verifyProof: bls12381_bbs_verify_proof
    }
}

module.exports.utilities = {
    convertToRevealMessageArray,
    convertRevealMessageArrayToRevealMap
}