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
import { utilities } from "../../../lib";

describe("bbs", () => {
  describe("bls12381_shake256", () => {
    describe("keyGen", () => {
      [
        {
          generateKeyFn: bbs.bls12381_shake256.generateKeyPair,
          secretKeyLength: bbs.bls12381_shake256.PRIVATE_KEY_LENGTH,
          publicKeyLength: bbs.bls12381_shake256.PUBLIC_KEY_LENGTH,
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
            Buffer.from(
              "SxLi4R28gWdxA6LHCZTc8hIYEjMcEqvMQOWF/po5Uz4=",
              "base64"
            )
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
          const result = await value.generateKeyFn({
            ikm: value.ikm,
            keyInfo: value.keyInfo,
          });
          expect(result.publicKey).toBeDefined();
          expect(result.secretKey).toBeDefined();
          expect(result.secretKey?.length as number).toEqual(
            value.secretKeyLength
          );
          expect(result.publicKey.length).toEqual(value.publicKeyLength);
          expect(result.secretKey as Uint8Array).toEqual(value.secretKey);
          expect(result.publicKey).toEqual(value.publicKey);
        });

        it("should be able to map a compressed public key to an uncompressed representation", async () => {
          const compressed_keypair = await bbs.bls12381_shake256.generateKeyPair({
            ikm: value.ikm,
            keyInfo: value.keyInfo,
          });

          const uncompressed_keypair = await bbs.bls12381_shake256.generateKeyPairUncompressed({
            ikm: value.ikm,
            keyInfo: value.keyInfo,
          });

          const uncompressed_from_compressed_pk = await utilities.compressedToUncompressedPublicKey(
            compressed_keypair.publicKey
          );

          const compressed_from_uncompressed_pk = await utilities.uncompressedToCompressedPublicKey(
            uncompressed_keypair.publicKey
          );

          expect(compressed_keypair.publicKey).toBeDefined();
          expect(compressed_keypair.secretKey).toBeDefined();

          expect(uncompressed_keypair.publicKey).toBeDefined();
          expect(uncompressed_keypair.secretKey).toBeDefined();
          expect(uncompressed_keypair.publicKey?.length as number).toEqual(
            bbs.bls12381_shake256.PUBLIC_KEY_LENGTH * 2
          )

          expect(uncompressed_from_compressed_pk).toBeDefined();
          expect(uncompressed_from_compressed_pk?.length as number).toEqual(
            bbs.bls12381_shake256.PUBLIC_KEY_LENGTH * 2
          )

          expect(uncompressed_keypair.publicKey).toEqual(uncompressed_from_compressed_pk)

          expect(compressed_from_uncompressed_pk).toBeDefined();
          expect(compressed_from_uncompressed_pk?.length as number).toEqual(
            bbs.bls12381_shake256.PUBLIC_KEY_LENGTH
          )

          expect(compressed_keypair.publicKey).toEqual(compressed_from_uncompressed_pk)
        });
      });

      it("should be able to generate a key pair from random", async () => {
        const result = await bbs.bls12381_shake256.generateKeyPair();

        expect(result.publicKey).toBeDefined();
        expect(result.secretKey).toBeDefined();
        expect(result.secretKey?.length as number).toEqual(
          bbs.bls12381_shake256.PRIVATE_KEY_LENGTH
        );
        expect(result.publicKey.length).toEqual(bbs.bls12381_shake256.PUBLIC_KEY_LENGTH);
      });

    });
  });
});
