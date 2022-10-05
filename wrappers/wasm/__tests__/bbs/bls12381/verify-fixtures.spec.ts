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

import { bbs } from "../../../lib/index";

import { SignatureFixture, bls12381Shake256SignatureFixtures } from "../../../__fixtures__";

bls12381Shake256SignatureFixtures.forEach((item: SignatureFixture) => {
  describe("bbs", () => {
    describe("bls12381_shake256", () => {
      describe("verify - test fixtures", () => {
        if (item.value.result.valid) {
          it(`should verify case: ${item.value.caseName}`, async () => {
            expect(
              (
                await bbs.bls12381_shake256.verify({
                  publicKey: new Uint8Array(
                    Buffer.from(item.value.signerKeyPair.publicKey, "hex")
                  ),
                  header: new Uint8Array(
                    Buffer.from(item.value.header, "hex")
                  ),
                  signature: new Uint8Array(
                    Buffer.from(item.value.signature, "hex")
                  ),
                  messages: item.value.messages.map(
                    (item) => new Uint8Array(Buffer.from(item, "hex"))
                  ),
                })
              ).verified
            ).toBeTruthy();
          });
        } else {
          it(`should fail to verify case: ${item.value.caseName} because ${item.value.result["reason"]}`, async () => {
            expect(
              (
                await bbs.bls12381_shake256.verify({
                  publicKey: new Uint8Array(
                    Buffer.from(item.value.signerKeyPair.publicKey, "hex")
                  ),
                  header: new Uint8Array(
                    Buffer.from(item.value.header, "hex")
                  ),
                  signature: new Uint8Array(
                    Buffer.from(item.value.signature, "hex")
                  ),
                  messages: item.value.messages.map(
                    (item) => new Uint8Array(Buffer.from(item, "hex"))
                  ),
                })
              ).verified
            ).toBeFalsy();
          });
        }
      });
    });
  });
});
