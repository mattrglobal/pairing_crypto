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

import { PairingCryptoError } from '@mattrglobal/pairing-crypto-rn';

/**
 * Additional information injected by react-native.
 */
type ReactNativeErrorLike = {
  message: string;
  stack?: string;
  code?: string;
  domain: string;
  userInfo: unknown;
  nativeStackIOS?: string[];
  nativeStackAndroid?: string[];
};

const formatError = (error: Error): unknown => {
  return {
    name: error.name,
    message: error.message,
    // NOTE: Excluded to reduce the noise, uncomment when needed
    // stack: error.stack?.split('\n'),
  };
};

const formatPairingCryptoError = (error: PairingCryptoError): unknown => {
  const cause = error.cause as ReactNativeErrorLike;
  const rawError = {
    message: cause?.message,
    code: cause?.code,
    domain: cause?.domain,
    userInfo: cause?.userInfo,
    nativeStackIOS: cause?.nativeStackIOS,
    nativeStackAndroid: cause?.nativeStackAndroid,
    // NOTE: Excluded to reduce the noise, uncomment when needed
    // stack: cause?.stack?.split('\n'),
  };
  return { message: error.message, cause: rawError };
};

export const inspect = (value: unknown, space = 2): string => {
  const replacer = (_key: string, value: unknown) => {
    // The stringify function only visits the object's enumerable own properties.
    // For error instances deserialized by react-native will becomes "{}". We need
    // to properly serialize them with a nicer format.
    if (value instanceof PairingCryptoError) {
      return formatPairingCryptoError(value);
    }
    if (value instanceof Error) {
      return formatError(value);
    }
    return value;
  };
  return JSON.stringify(value, replacer, space);
};
