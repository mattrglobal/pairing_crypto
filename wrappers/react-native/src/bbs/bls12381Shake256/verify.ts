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
import { BbsVerifyRequest, BbsVerifyResult, PairingCryptoError } from '../../types';

const { PairingCryptoRn } = NativeModules;

export const verify = async (request: BbsVerifyRequest): Promise<BbsVerifyResult> => {
  const { publicKey, messages, header, signature } = request;
  try {
    return {
      verified: await PairingCryptoRn.Bls12381Shake256Verify({
        publicKey: UInt8ArrayToArray(publicKey),
        messages: messages ? messages.map((item) => UInt8ArrayToArray(item)) : undefined,
        header: header ? UInt8ArrayToArray(header) : undefined,
        signature: UInt8ArrayToArray(signature),
      }),
    };
  } catch (err) {
    return {
      verified: false,
      error: new PairingCryptoError('Failed to verify Bbls12381Shake256 signature', err),
    };
  }
};
