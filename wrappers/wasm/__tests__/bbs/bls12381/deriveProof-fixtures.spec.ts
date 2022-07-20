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

import { BbsDeriveProofRequest, bbs } from "../../../lib";
import { stringToBytes } from "../../utilities";
import { SignatureFixture, signatureFixtures } from "../../../__fixtures__";

signatureFixtures.forEach((item: SignatureFixture) => {
  describe("bbs", () => {
    describe("bls12381", () => {
      describe("deriveProof - test fixtures", () => {
        if (item.value.result.valid) {
          it(`should deriveProof revealing all messages for case: ${item.value.caseName}`, async () => {
            const request: BbsDeriveProofRequest = {
              publicKey: new Uint8Array(
                Buffer.from(item.value.signerKeyPair.publicKey, "hex")
              ),
              header: new Uint8Array(
                Buffer.from(item.value.header, "hex")
              ),
              signature: new Uint8Array(
                Buffer.from(item.value.signature, "hex")
              ),
              messages: item.value.messages.map((item) => {
                return {
                  value: new Uint8Array(Buffer.from(item, "hex")),
                  reveal: true,
                };
              }),
              presentationMessage: stringToBytes("0123456789"),
            };

            const proof = await bbs.bls12381.deriveProof(request);
            expect(proof).toBeInstanceOf(Uint8Array);
          });

          it(`should deriveProof revealing no messages for case: ${item.value.caseName}`, async () => {
            const request: BbsDeriveProofRequest = {
              publicKey: new Uint8Array(
                Buffer.from(item.value.signerKeyPair.publicKey, "hex")
              ),
              header: new Uint8Array(
                Buffer.from(item.value.header, "hex")
              ),
              signature: new Uint8Array(
                Buffer.from(item.value.signature, "hex")
              ),
              messages: item.value.messages.map((item) => {
                return {
                  value: new Uint8Array(Buffer.from(item, "hex")),
                  reveal: false,
                };
              }),
              presentationMessage: stringToBytes("0123456789"),
            };

            const proof = await bbs.bls12381.deriveProof(request);
            expect(proof).toBeInstanceOf(Uint8Array);
          });

          if (item.value.messages.length > 1) {
            it(`should deriveProof revealing some messages for case: ${item.value.caseName}`, async () => {
              const messagesToReveal = [0]; // TODO could get more intelligent here
              const request: BbsDeriveProofRequest = {
                publicKey: new Uint8Array(
                  Buffer.from(item.value.signerKeyPair.publicKey, "hex")
                ),
                header: new Uint8Array(
                  Buffer.from(item.value.header, "hex")
                ),
                signature: new Uint8Array(
                  Buffer.from(item.value.signature, "hex")
                ),
                messages: item.value.messages.map((item, index) => {
                  return {
                    value: new Uint8Array(Buffer.from(item, "hex")),
                    reveal: messagesToReveal.includes(index) ? true : false,
                  };
                }),
                presentationMessage: stringToBytes("0123456789"),
              };

              const proof = await bbs.bls12381.deriveProof(request);
              expect(proof).toBeInstanceOf(Uint8Array);
            });
          }
        } else {
          it(`should fail to deriveProof for case: ${item.value.caseName} because ${item.value.result["reason"]}`, async () => {
            const request: BbsDeriveProofRequest = {
              publicKey: new Uint8Array(
                Buffer.from(item.value.signerKeyPair.publicKey, "hex")
              ),
              header: new Uint8Array(
                Buffer.from(item.value.header, "hex")
              ),
              signature: new Uint8Array(
                Buffer.from(item.value.signature, "hex")
              ),
              messages: item.value.messages.map((item) => {
                return {
                  value: new Uint8Array(Buffer.from(item, "hex")),
                  reveal: true,
                };
              }),
              presentationMessage: stringToBytes("0123456789"),
            };

            await expect(
              bbs.bls12381.deriveProof(request)
            ).rejects.toThrowError(
              "Error: signature verification failed."
            );
          });
        }
      });
    });
  });
});
