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

import { bbs_bound } from "../../../lib";

describe("bbs_bound", () => {
  describe("bls12381_bbs_g1_bls_sig_g2_sha256", () => {
    describe("keyGen", () => {
      [
        {
          generateBbsKeyFn: bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.generateBbsKeyPair,
          generateBlsKeyFn: bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.generateBlsKeyPair,
          bbsSecretKeyLength: bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.BBS_PRIVATE_KEY_LENGTH,
          bbsPublicKeyLength: bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.BBS_PUBLIC_KEY_LENGTH,
          blsSecretKeyLength: bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.BLS_PRIVATE_KEY_LENGTH,
          blsPublicKeyLength: bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.BLS_PUBLIC_KEY_LENGTH,
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
        },
      ].forEach((value) => {
        it(`should be able to generate a BBS key pair with an IKM and KeyInfo`, async () => {
          const result = await value.generateBbsKeyFn({
            ikm: value.ikm,
            keyInfo: value.keyInfo,
          });
          expect(result.publicKey).toBeDefined();
          expect(result.secretKey).toBeDefined();
          expect(result.secretKey?.length as number).toEqual(
            value.bbsSecretKeyLength
          );
          expect(result.publicKey.length).toEqual(value.bbsPublicKeyLength);
        });

        it(`should be able to generate a BLS key pair with an IKM and KeyInfo`, async () => {
          const result = await value.generateBlsKeyFn({
            ikm: value.ikm,
            keyInfo: value.keyInfo,
          });
          expect(result.publicKey).toBeDefined();
          expect(result.secretKey).toBeDefined();
          expect(result.secretKey?.length as number).toEqual(
            value.blsSecretKeyLength
          );
          expect(result.publicKey.length).toEqual(value.blsPublicKeyLength);
        });

        it("should be able to generate a BBS key pair from random", async () => {
          const result = await value.generateBbsKeyFn();

          expect(result.publicKey).toBeDefined();
          expect(result.secretKey).toBeDefined();
          expect(result.secretKey?.length as number).toEqual(
            value.bbsSecretKeyLength
          );
          expect(result.publicKey.length).toEqual(value.bbsPublicKeyLength);
        });

        it("should be able to generate a BLS key pair from random", async () => {
          const result = await value.generateBlsKeyFn();

          expect(result.publicKey).toBeDefined();
          expect(result.secretKey).toBeDefined();
          expect(result.secretKey?.length as number).toEqual(
            value.blsSecretKeyLength
          );
          expect(result.publicKey.length).toEqual(value.blsPublicKeyLength);
        });
      });
    });
  });
});