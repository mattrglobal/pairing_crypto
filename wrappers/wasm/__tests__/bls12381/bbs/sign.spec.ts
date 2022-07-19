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
import { BbsSignRequest, bbs, KeyPair } from "../../../lib";
import { stringToBytes } from "../../utilities";

describe("bbs", () => {
  describe("ciphersuites", () => {
    describe("bls12381", () => {
      let keyPair: KeyPair;

      beforeAll(async () => {
        keyPair = await bbs.ciphersuites.bls12381.generateKeyPair(
          randomBytes(32),
          randomBytes(32),
        );
      });

      describe("sign", () => {
        it("should sign a single message", async () => {
          const request: BbsSignRequest = {
            secretKey: keyPair.secretKey,
            publicKey: keyPair.publicKey,
            messages: [stringToBytes("ExampleMessage")],
          };
          const signature = await bbs.ciphersuites.bls12381.sign(request);
          expect(signature).toBeInstanceOf(Uint8Array);
          expect(signature.length).toEqual(bbs.ciphersuites.bls12381.SIGNATURE_LENGTH);
        });

        it("should sign multiple messages", async () => {
          const request: BbsSignRequest = {
            secretKey: keyPair.secretKey,
            publicKey: keyPair.publicKey,
            messages: [
              stringToBytes("ExampleMessage"),
              stringToBytes("ExampleMessage2"),
              stringToBytes("ExampleMessage3"),
            ],
          };
          const signature = await bbs.ciphersuites.bls12381.sign(request);
          expect(signature).toBeInstanceOf(Uint8Array);
          expect(signature.length).toEqual(bbs.ciphersuites.bls12381.SIGNATURE_LENGTH);
        });

        it("should throw error if secret key not present", async () => {
          const request: any = {
            secretKey: undefined,
            publicKey: keyPair.publicKey,
            messages: [
              stringToBytes("ExampleMessage"),
              stringToBytes("ExampleMessage2"),
              stringToBytes("ExampleMessage3"),
            ],
          };
          await expect(bbs.ciphersuites.bls12381.sign(request)).rejects.toThrowError(
            "Request object missing required element"
          );
        });

        it("should throw error if public key not present", async () => {
          const request: any = {
            secretKey: keyPair.secretKey,
            publicKey: undefined,
            messages: [
              stringToBytes("ExampleMessage"),
              stringToBytes("ExampleMessage2"),
              stringToBytes("ExampleMessage3"),
            ],
          };
          await expect(bbs.ciphersuites.bls12381.sign(request)).rejects.toThrowError(
            "Request object missing required element"
          );
        });

        it("should throw error if secret length is too small", async () => {
          const request: BbsSignRequest = {
            secretKey: keyPair.secretKey?.slice(0, 10) ?? undefined,
            publicKey: keyPair.publicKey,
            messages: [
              stringToBytes("ExampleMessage"),
              stringToBytes("ExampleMessage2"),
              stringToBytes("ExampleMessage3"),
            ],
          };
          await expect(bbs.ciphersuites.bls12381.sign(request)).rejects.toThrowError(
            "Error: vector to fixed-sized array conversion failed"
          );
        });

        it("should throw error if secret length is too large", async () => {
          const request: BbsSignRequest = {
            secretKey: new Uint8Array([
              ...keyPair.secretKey,
              ...keyPair.secretKey,
            ]),
            publicKey: keyPair.publicKey,
            messages: [
              stringToBytes("ExampleMessage"),
              stringToBytes("ExampleMessage2"),
              stringToBytes("ExampleMessage3"),
            ],
          };
          await expect(bbs.ciphersuites.bls12381.sign(request)).rejects.toThrowError(
            "Error: vector to fixed-sized array conversion failed"
          );
        });

        it("should throw error when messages are empty and header is absent", async () => {
          const request: BbsSignRequest = {
            secretKey: keyPair.secretKey,
            publicKey: keyPair.publicKey,
            messages: [],
          };
          await expect(bbs.ciphersuites.bls12381.sign(request)).rejects.toThrowError(
            "Error: bad arguments: cause: nothing to sign"
          );
        });

        it("should throw when secret key invalid", async () => {
          const request: BbsSignRequest = {
            secretKey: new Uint8Array(32),
            publicKey: keyPair.publicKey,
            messages: [
              stringToBytes("ExampleMessage"),
              stringToBytes("ExampleMessage2"),
              stringToBytes("ExampleMessage3"),
            ],
          };
          await expect(bbs.ciphersuites.bls12381.sign(request)).rejects.toThrowError(
            "Error: secret key is not valid."
          );
        });
      });
    });
  });
});
