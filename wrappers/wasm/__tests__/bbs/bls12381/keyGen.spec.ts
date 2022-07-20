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

import { bbs } from "../../../lib";
import { base64Encode } from "../../utilities";

describe("bbs", () => {
  describe("bls12381", () => {
    describe("keyGen", () => {
      [
        {
          generateKeyFn: bbs.bls12381.generateKeyPair,
          secretKeyLength: bbs.bls12381.PRIVATE_KEY_LENGTH,
          publicKeyLength: bbs.bls12381.PUBLIC_KEY_LENGTH,
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
            Buffer.from("SxLi4R28gWdxA6LHCZTc8hIYEjMcEqvMQOWF/po5Uz4=", "base64")
          ),
          publicKey: new Uint8Array(
            Buffer.from(
              "lom+pndcCeNHp1J2C+mF4NTg/epCZ0/DYVKzk8Doypvcmg9mAXhMAya1m9gwG297GGNNClwtDamiZbIva7v+a9v2ztMm17M2b2v6Vg/whD5BJ72YhkQruQL0Cn59V6Ny",
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
});
