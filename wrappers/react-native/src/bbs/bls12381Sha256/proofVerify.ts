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

import { NativeModules } from 'react-native';
import { UInt8ArrayToArray, mapObjIndexed } from '../../utilities';
import { BbsVerifyProofRequest, BbsVerifyResult, PairingCryptoError } from '../../types';

const { PairingCryptoRn } = NativeModules;

export const proofVerify = async (request: BbsVerifyProofRequest): Promise<BbsVerifyResult> => {
  const { publicKey, header, presentationHeader, totalMessageCount, proof, messages } = request;
  try {
    return {
      verified: await PairingCryptoRn.Bls12381Sha256ProofVerify({
        publicKey: UInt8ArrayToArray(publicKey),
        proof: UInt8ArrayToArray(proof),
        header: header ? UInt8ArrayToArray(header) : undefined,
        presentationHeader: presentationHeader ? UInt8ArrayToArray(presentationHeader) : undefined,
        messages: messages ? mapObjIndexed(UInt8ArrayToArray, messages) : undefined,
        totalMessageCount,
      }),
    };
  } catch (err) {
    return {
      verified: false,
      error: new PairingCryptoError('Failed to verify Bbls12381Sha256 proof', err),
    };
  }
};
