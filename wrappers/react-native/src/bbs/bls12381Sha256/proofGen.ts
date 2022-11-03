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

import { NativeModules } from 'react-native';
import { UInt8ArrayToArray } from '../../utilities';
import { BbsDeriveProofRequest, PairingCryptoError } from '../../types';

const { PairingCryptoRn } = NativeModules;

export const proofGen = async (request: BbsDeriveProofRequest): Promise<Uint8Array> => {
  const { publicKey, header, presentationHeader, signature, verifySignature, messages } = request;
  try {
    const result = await PairingCryptoRn.Bls12381Sha256ProofGen({
      publicKey: UInt8ArrayToArray(publicKey),
      signature: UInt8ArrayToArray(signature),
      header: header ? UInt8ArrayToArray(header) : undefined,
      presentationHeader: presentationHeader ? UInt8ArrayToArray(presentationHeader) : undefined,
      messages: messages
        ? messages.map((item) => ({
            value: UInt8ArrayToArray(item.value),
            reveal: item.reveal,
          }))
        : undefined,
      verifySignature,
    });
    return new Uint8Array(result);
  } catch (err) {
    throw new PairingCryptoError('Failed to generate proof', err);
  }
};
