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

import { Buffer } from 'buffer';

/**
 * Converts a Uint8Array to a base64 string
 * @param array A Uint8Array
 *
 * @returns A Base64 string
 */
export const UInt8ArrayToBase64String = (array: Uint8Array): string => Buffer.from(array.buffer).toString('base64');

/**
 * Converts a Uint8Array to a numerical array
 * @param array A Uint8Array
 *
 * @returns A numericalArray
 */
export const UInt8ArrayToArray = (array: Uint8Array): Array<number> => [].slice.call(array);

/**
 * Converts a base64 string to a Uint8Array
 * @param string A Base64 string
 *
 * @returns A Uint8Array
 */
export const base64StringToUInt8Array = (string: string): Uint8Array => new Uint8Array(Buffer.from(string, 'base64'));

/**
 * Convert values in the object with the given function.
 *
 * @returns The transformed object
 */
export const mapObjIndexed = <K extends number | string, V, R>(
  fn: (value: V, key: K, obj: Record<K, V>) => R,
  obj: Record<K, V>
): Record<K, R> => {
  return Object.keys(obj).reduce((accu, next) => {
    const key = next as K;
    accu[key] = fn(obj[key], key, obj);
    return accu;
  }, {} as Record<K, R>);
};

export const convertToRevealMessageArray = (messages: any, revealedIndicies: any): any => {
    let revealMessages: any = [];
    let i = 0;
    messages.forEach((element: any) => {
        if (revealedIndicies.includes(i)) {
            revealMessages.push({ value: element, reveal: true });
        } else {
            revealMessages.push({ value: element, reveal: false });
        }
        i++;
    })
    return revealMessages;
}

export const convertRevealMessageArrayToRevealMap = (messages: any): any => {
    return messages.reduce(
      (map: any, item: any, index: any) => {
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
