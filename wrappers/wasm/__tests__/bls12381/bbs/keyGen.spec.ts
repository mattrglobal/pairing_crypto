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

import { bls12381 } from "../../../lib";

describe("bls12381", () => {
  describe("keyGen", () => {
    [
      {
        generateKeyFn: bls12381.bbs.generateKeyPair,
        secretKeyLength: bls12381.bbs.PRIVATE_KEY_LENGTH,
        publicKeyLength: bls12381.bbs.PUBLIC_KEY_LENGTH,
        ikm: new Uint8Array(
          Buffer.from(
            "ZEdocGN5MUpVeTFxZFhOMExXRnVMVlJsYzNRdFNVdE5MWFJ2TFdkbGJtVnlZWFJsTFNSbEtISkFkQ010YTJWNQ==",
            "base64"
          )
        ),
        keyInfo: new Uint8Array(
          Buffer.from(
            "WkVkb2NHTjVNVXBWZVRGNllqSXhiRXhYZEd4bFV6RjBXbGhTYUZwSFJqQlpVekV3WW5reGFWcFRNVEZqTWxaclRGZHNkVXhZVW14ak0xRjBZVEpXTlV4WFpHeGlaejA5",
            "base64"
          )
        ),
        secretKey: new Uint8Array(
          Buffer.from("VWpsTWREVnFjVEIzZVd0S1MzcFJjWFJUWVhoQ05USTRTbHBYU21aVk9IRnpkRFZPYUVKNUsyWldXVDA9", "base64")
        ),
        publicKey: new Uint8Array(
          Buffer.from(
            "ZEd4ME9IWXZWRzlITTBrd1ZuRkZOVTV5WVRoNE0yOUlhUzlaY0VZeVdIcHlhRTFZUVVoSmEyNWtabUZ3SzNkaU1rTjFRbWx5V1VKdFFVMU1VbUpxTmtaYWQxWllPRTlGUjNCeVZVSkdORE5HYUhsbVJGcHdVRTVvZFZSNk9YaHVNREpZZW5ab2J6VnFiR0Z4Um5veE5sWmxRV0pUYnpOVFUxVTFMM1ZSTW00PQ==",
            "base64"
          )
        ),
      },
    ].forEach((value) => {
      it(`should be able to generate a key pair with an IKM and KeyInfo`, async () => {
        const result = await value.generateKeyFn(value.ikm, value.keyInfo);
        expect(result.publicKey).toBeDefined();
        expect(result.secretKey).toBeDefined();
        expect(result.secretKey?.length as number).toEqual(
          value.secretKeyLength
        );
        expect(result.publicKey.length).toEqual(value.publicKeyLength);
        expect(result.secretKey as Uint8Array).toEqual(value.secretKey);
        expect(result.publicKey).toEqual(value.publicKey);
      });
    });
  });
});
