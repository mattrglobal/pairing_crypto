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

import { Buffer } from 'buffer';

/**
 * Converts a Uint8Array to a base64 string
 * @param array A Uint8Array
 *
 * @returns A Base64 string
 */
export const UInt8ArrayToBase64String = (array: Uint8Array): string =>
  new Buffer(array.buffer).toString('base64');

/**
 * Converts a Uint8Array to a numerical array
 * @param array A Uint8Array
 *
 * @returns A numericalArray
 */
export const UInt8ArrayToArray = (array: Uint8Array): Array<number> =>
  [].slice.call(array);

/**
 * Converts a base64 string to a Uint8Array
 * @param string A Base64 string
 *
 * @returns A Uint8Array
 */
export const base64StringToUInt8Array = (string: string): Uint8Array =>
  new Uint8Array(new Buffer(string, 'base64'));
