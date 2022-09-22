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

import { randomBytes } from "@stablelib/random";
import { BbsBoundSignRequest, bbs_bound, KeyPair } from "../../../lib";
import { stringToBytes } from "../../utilities";

describe("bbs_bound", () => {
  describe("bls12381_bbs_g1_bls_sig_g2_sha256", () => {
    let bbsKeyPair: KeyPair;
    let blsKeyPair: KeyPair;

    beforeAll(async () => {
      bbsKeyPair = await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.generateBbsKeyPair(
        {
          ikm: randomBytes(32),
          keyInfo: randomBytes(32),
        }
      );


      blsKeyPair = await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.generateBlsKeyPair(
        {
          ikm: randomBytes(32),
          keyInfo: randomBytes(32),
        }
      );
    });

    describe("sign", () => {
      it("should sign a header", async () => {
        const request: BbsBoundSignRequest = {
          secretKey: bbsKeyPair.secretKey,
          publicKey: bbsKeyPair.publicKey,
          blsPublicKey: blsKeyPair.publicKey,
          header: stringToBytes("Its a header"),
        };
        const signature = await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(request);
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toEqual(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.BBS_SIGNATURE_LENGTH);
      });

      it("should sign a single message", async () => {
        const request: BbsBoundSignRequest = {
          secretKey: bbsKeyPair.secretKey,
          publicKey: bbsKeyPair.publicKey,
          blsPublicKey: blsKeyPair.publicKey,
          messages: [stringToBytes("ExampleMessage")],
        };
        const signature = await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(request);
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toEqual(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.BBS_SIGNATURE_LENGTH);
      });

      it("should sign multiple messages", async () => {
        const request: BbsBoundSignRequest = {
          secretKey: bbsKeyPair.secretKey,
          publicKey: bbsKeyPair.publicKey,
          blsPublicKey: blsKeyPair.publicKey,
          messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        const signature = await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(request);
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toEqual(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.BBS_SIGNATURE_LENGTH);
      });

      it("should throw error if neither messages or header supplied", async () => {
        const request: any = {
          secretKey: bbsKeyPair.secretKey,
          publicKey: bbsKeyPair.publicKey,
          blsPublicKey: blsKeyPair.publicKey,
        };
        await expect(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(request)).rejects.toThrowError(
          "Error: bad arguments: cause: nothing to sign"
        );
      });

      it("should throw error if bbs secret key not present", async () => {
        const request: any = {
          secretKey: undefined,
          publicKey: bbsKeyPair.publicKey,
          blsPublicKey: blsKeyPair.publicKey, messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        await expect(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(request)).rejects.toThrowError(
          "Request object missing required element"
        );
      });

      it("should throw error if bbs public key not present", async () => {
        const request: any = {
          secretKey: bbsKeyPair.secretKey,
          publicKey: undefined,
          blsPublicKey: blsKeyPair.publicKey,
          messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        await expect(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(request)).rejects.toThrowError(
          "Request object missing required element"
        );
      });

      it("should throw error if bls public key not present", async () => {
        const request: any = {
          secretKey: bbsKeyPair.secretKey,
          publicKey: bbsKeyPair.publicKey,
          blsPublicKey: undefined,
          messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        await expect(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(request)).rejects.toThrowError(
          "Request object missing required element"
        );
      });

      it("should throw error if secret length is too small", async () => {
        const request: BbsBoundSignRequest = {
          secretKey: bbsKeyPair.secretKey?.slice(0, 10) ?? undefined,
          publicKey: bbsKeyPair.publicKey,
          blsPublicKey: blsKeyPair.publicKey,
          messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        await expect(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(request)).rejects.toThrowError(
          "Error: vector to fixed-sized array conversion failed"
        );
      });

      it("should throw error if secret length is too large", async () => {
        const request: BbsBoundSignRequest = {
          secretKey: new Uint8Array([
            ...bbsKeyPair.secretKey,
            ...bbsKeyPair.secretKey,
          ]),
          publicKey: bbsKeyPair.publicKey,
          blsPublicKey: blsKeyPair.publicKey,
          messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        await expect(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(request)).rejects.toThrowError(
          "Error: vector to fixed-sized array conversion failed"
        );
      });

      it("should throw error when messages are empty and header is absent", async () => {
        const request: BbsBoundSignRequest = {
          secretKey: bbsKeyPair.secretKey,
          publicKey: bbsKeyPair.publicKey,
          blsPublicKey: blsKeyPair.publicKey,
          messages: [],
        };
        await expect(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(request)).rejects.toThrowError(
          "Error: bad arguments: cause: nothing to sign"
        );
      });

      it("should throw when secret key invalid", async () => {
        const request: BbsBoundSignRequest = {
          secretKey: new Uint8Array(32),
          publicKey: bbsKeyPair.publicKey,
          blsPublicKey: blsKeyPair.publicKey,
          messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        await expect(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(request)).rejects.toThrowError(
          "Error: secret key is not valid."
        );
      });
    });
  });
});
