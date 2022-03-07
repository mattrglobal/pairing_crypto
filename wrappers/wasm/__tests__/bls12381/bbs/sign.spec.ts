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

import { BbsSignRequest, bls12381, KeyPair } from "../../../lib";
import { stringToBytes } from "../../utilities";

describe("bls12381", () => {
  describe("bbs", () => {
    let blsKeyPair: KeyPair;

    beforeAll(async () => {
      blsKeyPair = await bls12381.generateG2KeyPair();
    });

    describe("sign", () => {
      it("should sign a single message", async () => {
        const request: BbsSignRequest = {
          secretKey: blsKeyPair.secretKey,
          messages: [stringToBytes("ExampleMessage")],
        };
        const signature = await bls12381.bbs.sign(request);
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toEqual(bls12381.bbs.SIGNATURE_LENGTH);
      });

      it("should sign multiple messages", async () => {
        const request: BbsSignRequest = {
          secretKey: blsKeyPair.secretKey,
          messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        const signature = await bls12381.bbs.sign(request);
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toEqual(bls12381.bbs.SIGNATURE_LENGTH);
      });

      it("should throw error if secret key not present", async () => {
        const request: any = {
          secretKey: undefined,
          messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        await expect(bls12381.bbs.sign(request)).rejects.toThrowError(
          "Request object missing required element"
        );
      });

      it("should throw error if secret length is too small", async () => {
        const request: BbsSignRequest = {
          secretKey: blsKeyPair.secretKey?.slice(0, 10) ?? undefined,
          messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        await expect(bls12381.bbs.sign(request)).rejects.toThrowError(
          "Error: Failed to parse secret key"
        );
      });

      it("should throw error if secret length is too large", async () => {
        const request: BbsSignRequest = {
          secretKey: new Uint8Array([
            ...blsKeyPair.secretKey,
            ...blsKeyPair.secretKey,
          ]),
          messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        await expect(bls12381.bbs.sign(request)).rejects.toThrowError(
          "Error: Failed to parse secret key"
        );
      });

      it("should throw error when messages empty", async () => {
        const request: BbsSignRequest = {
          secretKey: blsKeyPair.secretKey,
          messages: [],
        };
        await expect(bls12381.bbs.sign(request)).rejects.toThrowError(
          "Messages to sign empty, expected > 1"
        );
      });

      it("should throw when secret key invalid", async () => {
        const request: BbsSignRequest = {
          secretKey: new Uint8Array(32),
          messages: [
            stringToBytes("ExampleMessage"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        await expect(bls12381.bbs.sign(request)).rejects.toThrowError(
          "Error: invalid secret key"
        );
      });
    });
  });
});
