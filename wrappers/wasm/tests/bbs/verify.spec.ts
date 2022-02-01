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

import {
  bls12381BbsVerify,
  bls12381BbsSign,
  bls12381GenerateG2KeyPair,
  BlsKeyPair,
  BbsVerifyRequest,
  BbsSignRequest,
} from "../../lib/index";
import { base64Decode, stringToBytes } from "../utilities";

describe("bbs", () => {
  describe("bls12381BbsVerify", () => {
    let blsKeyPair: BlsKeyPair;

    beforeAll(async () => {
      blsKeyPair = await bls12381GenerateG2KeyPair();
    });

    it("should throw error when signature wrong length", async () => {
      const request: BbsVerifyRequest = {
        publicKey: blsKeyPair.publicKey,
        messages: [stringToBytes("ExampleMessage")],
        signature: base64Decode("jYidhsdqxvAyNXMV4/vNfGM/4AULfSyf"),
      };
      expect((await bls12381BbsVerify(request)).verified).toBeFalsy();
    });

    it("should verify valid signature with a single message", async () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.secretKey,
        messages: [stringToBytes("ExampleMessage")],
      };
      const signature = await bls12381BbsSign(request);
      const verifyRequest: BbsVerifyRequest = {
        publicKey: blsKeyPair.publicKey,
        messages: [stringToBytes("ExampleMessage")],
        signature,
      };
      expect((await bls12381BbsVerify(verifyRequest)).verified).toBeTruthy();
    });

    it("should verify valid signature with multiple messages", async () => {
      const request: BbsSignRequest = {
        secretKey: blsKeyPair.secretKey,
        messages: [
          stringToBytes("ExampleMessage"),
          stringToBytes("ExampleMessage2"),
          stringToBytes("ExampleMessage3"),
        ],
      };
      const signature = await bls12381BbsSign(request);
      const verifyRequest: BbsVerifyRequest = {
        publicKey: blsKeyPair.publicKey,
        messages: [
          stringToBytes("ExampleMessage"),
          stringToBytes("ExampleMessage2"),
          stringToBytes("ExampleMessage3"),
        ],
        signature,
      };
      expect((await bls12381BbsVerify(verifyRequest)).verified).toBeTruthy();
    });

    it("should not verify valid signature with wrong single message", async () => {
      const messages = [stringToBytes("BadMessage")];
      const verifyRequest: BbsVerifyRequest = {
        publicKey: blsKeyPair.publicKey,
        messages,
        signature: base64Decode(
          "kTV8dar9xLWQZ5EzaWYqTRmgA6dw6wcrUw5c///crRD2QQPXX9Di+lgCPCXAA5D8Pytuh6bNSx6k4NZTR9KfSNdaejKl2zTU9poRfzZ2SIskdgSHTZ2y7jLm/UEGKsAs3tticBVj1Pm2GNhQI/OlXQ=="
        ),
      };
      expect((await bls12381BbsVerify(verifyRequest)).verified).toBeFalsy();
    });

    it("should not verify valid signature with wrong messages", async () => {
      const messages = [
        stringToBytes("BadMessage"),
        stringToBytes("BadMessage"),
        stringToBytes("BadMessage"),
      ];
      const verifyRequest: BbsVerifyRequest = {
        publicKey: blsKeyPair.publicKey,
        messages,
        signature: base64Decode(
          "jYidhsdqxvAyNXMV4/vNfGM/4AULfSyfvQiwh+dDd4JtnT5xHnwpzMYdLdHzBYwXaGE1k6ln/pwtI4RwQZpl03SCv/mT/3AdK8PB2y43MGdMSeGTyZGfZf+rUrEDEs3lTfmPK54E+JBzd96gnrF2iQ=="
        ),
      };
      expect((await bls12381BbsVerify(verifyRequest)).verified).toBeFalsy();
    });

    it("should not verify when messages empty", async () => {
      const request: BbsVerifyRequest = {
        publicKey: blsKeyPair.publicKey,
        messages: [],
        signature: base64Decode(
          "jYidhsdqxvAyNXMV4/vNfGM/4AULfSyfvQiwh+dDd4JtnT5xHnwpzMYdLdHzBYwXaGE1k6ln/pwtI4RwQZpl03SCv/mT/3AdK8PB2y43MGdMSeGTyZGfZf+rUrEDEs3lTfmPK54E+JBzd96gnrF2iQ=="
        ),
      };
      expect((await bls12381BbsVerify(request)).verified).toBeFalsy();
    });

    it("should not verify when public key invalid length", async () => {
      const request: BbsVerifyRequest = {
        publicKey: new Uint8Array(20),
        messages: [],
        signature: base64Decode(
          "jYidhsdqxvAyNXMV4/vNfGM/4AULfSyfvQiwh+dDd4JtnT5xHnwpzMYdLdHzBYwXaGE1k6ln/pwtI4RwQZpl03SCv/mT/3AdK8PB2y43MGdMSeGTyZGfZf+rUrEDEs3lTfmPK54E+JBzd96gnrF2iQ=="
        ),
      };
      expect((await bls12381BbsVerify(request)).verified).toBeFalsy();
    });
  });
});
