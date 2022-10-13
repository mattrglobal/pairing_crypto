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
import { UInt8ArrayToArray } from '../../utilities';
import { KeyPair, KeyGenerationRequest, PairingCryptoError } from '../../types';

const { PairingCryptoRn } = NativeModules;

export const generateKeyPair = async (request?: KeyGenerationRequest): Promise<Required<KeyPair>> => {
  try {
    const result = await PairingCryptoRn.Bls12381Shake256GenerateKeyPair(
      request
        ? {
            ikm: request.ikm ? UInt8ArrayToArray(request.ikm) : undefined,
            keyInfo: request.keyInfo ? UInt8ArrayToArray(request.keyInfo) : undefined,
          }
        : {}
    );
    return {
      publicKey: new Uint8Array(result.publicKey),
      secretKey: new Uint8Array(result.secretKey),
    };
  } catch (err) {
    throw new PairingCryptoError('Failed to generate key pair', err);
  }
};
