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

import { bls12381 } from "../../../lib/index";

import { ProofFixture, proofFixtures } from "../../../__fixtures__";

proofFixtures.forEach((item: ProofFixture) => {
  describe("bls12381", () => {
    describe("bbs", () => {
      describe("verifyProof - test fixtures", () => {
        if (item.value.result.valid) {
          it(`should verify case: ${item.value.caseName}`, async () => {
            expect(
              await bls12381.bbs.verifyProof({
                publicKey: new Uint8Array(
                  Buffer.from(item.value.signerPublicKey, "hex")
                ),
                proof: new Uint8Array(Buffer.from(item.value.proof, "hex")),
                presentationMessage: new Uint8Array(
                  Buffer.from(item.value.presentationMessage, "hex")
                ),
                totalMessageCount: item.value.totalMessageCount,
                messages: Object.entries(item.value.revealedMessages).reduce(
                  (map, val, _) => {
                    const key = parseInt(val[0]);
                    const message = new Uint8Array(Buffer.from(val[1], "hex"));
                    map = {
                      ...map,
                      [key]: message,
                    };
                    return map;
                  },
                  {}
                ),
              })
            ).toBeTruthy();
          });
        } else {
          it(`should fail to verify case: ${item.value.caseName} because ${item.value.result["reason"]}`, async () => {
            expect(
              (
                await bls12381.bbs.verifyProof({
                  publicKey: new Uint8Array(
                    Buffer.from(item.value.signerPublicKey, "hex")
                  ),
                  proof: new Uint8Array(Buffer.from(item.value.proof, "hex")),
                  presentationMessage: new Uint8Array(
                    Buffer.from(item.value.presentationMessage, "hex")
                  ),
                  totalMessageCount: item.value.totalMessageCount,
                  messages: Object.entries(item.value.revealedMessages).reduce(
                    (map, val, _) => {
                      const key = parseInt(val[0]);
                      const message = new Uint8Array(
                        Buffer.from(val[1], "hex")
                      );

                      map = {
                        ...map,
                        [key]: message,
                      };

                      return map;
                    },
                    {}
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
