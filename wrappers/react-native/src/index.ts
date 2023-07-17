/*
 * Copyright 2022 - MATTR Limited
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

import { bls12381Sha256, bls12381Shake256 } from './bbs';

export * from './types';

import { convertToRevealMessageArray, convertRevealMessageArrayToRevealMap } from './utilities';

export const utilities = { convertToRevealMessageArray, convertRevealMessageArrayToRevealMap };

export const bbs = {
  bls12381_sha256: {
    PRIVATE_KEY_LENGTH: 32,
    PUBLIC_KEY_LENGTH: 96,
    SIGNATURE_LENGTH: 80,

    generateKeyPair: bls12381Sha256.generateKeyPair,
    sign: bls12381Sha256.sign,
    verify: bls12381Sha256.verify,
    proofGen: bls12381Sha256.proofGen,
    proofVerify: bls12381Sha256.proofVerify,
  },
  bls12381_shake256: {
    PRIVATE_KEY_LENGTH: 32,
    PUBLIC_KEY_LENGTH: 96,
    SIGNATURE_LENGTH: 80,

    generateKeyPair: bls12381Shake256.generateKeyPair,
    sign: bls12381Shake256.sign,
    verify: bls12381Shake256.verify,
    proofGen: bls12381Shake256.proofGen,
    proofVerify: bls12381Shake256.proofVerify,
  },
};
