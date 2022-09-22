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
import { BlsKeyPopGenRequest, BlsKeyPopVerifyRequest, bbs_bound, KeyPair } from "../../../lib";
import { stringToBytes } from "../../utilities";

describe("bbs_bound", () => {
  describe("bls12381_bbs_g1_bls_sig_g2_sha256", () => {
    let blsKeyPair: KeyPair;

    beforeAll(async () => {

      blsKeyPair = await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.generateBlsKeyPair(
        {
          ikm: randomBytes(32),
          keyInfo: randomBytes(32),
        }
      );
    });

    describe("keyPopVerify", () => {
      it("should validate a proof of posession for BLS secret key", async () => {
        const request: BlsKeyPopGenRequest = {
          blsSecretKey: blsKeyPair.secretKey,
          aud: stringToBytes("test-issuer-001"),
          dst: stringToBytes("test-dst"),
          extraInfo: stringToBytes("test-info"),
        };
        const blsKeyPop = await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.blsKeyPopGen(request);
        expect(blsKeyPop).toBeInstanceOf(Uint8Array);
        expect(blsKeyPop.length).toEqual(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.BLS_KEY_POP_LENGTH);

        const verifyRequest: BlsKeyPopVerifyRequest = {
          blsKeyPop,
          blsPublicKey: blsKeyPair.publicKey,
          aud: stringToBytes("test-issuer-001"),
          dst: stringToBytes("test-dst"),
          extraInfo: stringToBytes("test-info"),
        };
        expect(
          (
            await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.blsKeyPopVerify(
              verifyRequest
            )
          ).verified
        ).toBeTruthy();
      });
    });
  });
});
