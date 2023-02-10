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
import {
  BbsBoundSignRequest,
  BbsBoundDeriveProofRequest,
  BbsBoundVerifyProofRequest,
  bbs_bound,
  KeyPair,
} from "../../../lib";
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

    describe("verifyProof", () => {
      it("should verify a proof", async () => {
        const signRequest: BbsBoundSignRequest = {
          secretKey: bbsKeyPair.secretKey,
          publicKey: bbsKeyPair.publicKey,
          blsPublicKey: blsKeyPair.publicKey,
          header: stringToBytes("Its a header"),
          messages: [
            stringToBytes("ExampleMessage1"),
            stringToBytes("ExampleMessage2"),
            stringToBytes("ExampleMessage3"),
          ],
        };
        const signature = await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.sign(
          signRequest
        );
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toEqual(
          bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.BBS_SIGNATURE_LENGTH
        );

        const deriveProofRequest: BbsBoundDeriveProofRequest = {
          publicKey: bbsKeyPair.publicKey,
          blsSecretKey: blsKeyPair.secretKey,
          header: stringToBytes("Its a header"),
          presentationHeader: stringToBytes("Its a presentation header"),
          signature,
          verifySignature: true,
          messages: [
            {
              value: stringToBytes("ExampleMessage1"),
              reveal: true,
            },
            {
              value: stringToBytes("ExampleMessage2"),
              reveal: true,
            },
            {
              value: stringToBytes("ExampleMessage3"),
              reveal: false,
            },
          ],
        };

        const proof = await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.deriveProof(
          deriveProofRequest
        );
        expect(proof).toBeInstanceOf(Uint8Array);

        const verifyProofRequest: BbsBoundVerifyProofRequest = {
          publicKey: bbsKeyPair.publicKey,
          header: stringToBytes("Its a header"),
          presentationHeader: stringToBytes("Its a presentation header"),
          proof,
          messages: {
            0: stringToBytes("ExampleMessage1"),
            1: stringToBytes("ExampleMessage2"),
          },
        };

        expect(
          (
            await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.verifyProof(
              verifyProofRequest
            )
          ).verified
        ).toBeTruthy();
      });
    });
  });
});
