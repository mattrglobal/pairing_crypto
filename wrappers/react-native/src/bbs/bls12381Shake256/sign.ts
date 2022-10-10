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
import type { BbsSignRequest } from '../../types';

const { PairingCryptoRn } = NativeModules;

export const sign = async (request: BbsSignRequest): Promise<Uint8Array> => {
  const { secretKey, publicKey, messages, header } = request;
  try {
    return new Uint8Array(
      await PairingCryptoRn.Bls12381Shake256Sign({
        publicKey: UInt8ArrayToArray(publicKey),
        secretKey: UInt8ArrayToArray(secretKey),
        messageCount: messages?.length ?? 0,
        messages: messages ? messages.map((_) => UInt8ArrayToArray(_)) : [],
        header,
      })
    );
  } catch {
    throw new Error('Failed to sign');
  }
};
