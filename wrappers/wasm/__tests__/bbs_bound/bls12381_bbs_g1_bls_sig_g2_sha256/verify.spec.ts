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
import { BbsBoundVerifyRequest, bbs_bound, KeyPair } from "../../../lib/index";
import { base64Decode, stringToBytes } from "../../utilities";

describe("bbs_bound", () => {
  describe("bls12381_bbs_g1_bls_sig_g2_sha256", () => {
    describe("verify", () => {
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

      it("should throw error when signature wrong length", async () => {
        const request: BbsBoundVerifyRequest = {
          publicKey: bbsKeyPair.publicKey,
          blsSecretKey: blsKeyPair.secretKey,
          messages: [stringToBytes("ExampleMessage")],
          signature: base64Decode("jYidhsdqxvAyNXMV4/vNfGM/4AULfSyf"),
        };
        await expect(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.verify(request)).rejects.toThrowError(
          "Error: vector to fixed-sized array conversion failed"
        );
      });

      // TODO fixture
      it("should not verify valid signature with wrong single message", async () => {
        const messages = [stringToBytes("BadMessage")];
        const verifyRequest: BbsBoundVerifyRequest = {
          publicKey: bbsKeyPair.publicKey,
          blsSecretKey: blsKeyPair.secretKey,
          messages,
          signature: base64Decode(
            "iWIbLh10y1BkB6h+6ILXg6pJTKanCcE5C+IaRlxeNqk4GpygZywGxopHgnGD7KNUW8kT4rslyHoud5gML2luEiSqT0MsX63OTysfj2Y2nXM="
          ),
        };
        expect((await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.verify(verifyRequest)).verified).toBeFalsy();
      });

      it("should not verify valid signature with wrong messages", async () => {
        const messages = [
          stringToBytes("BadMessage"),
          stringToBytes("BadMessage"),
          stringToBytes("BadMessage"),
        ];
        const verifyRequest: BbsBoundVerifyRequest = {
          publicKey: bbsKeyPair.publicKey,
          blsSecretKey: blsKeyPair.secretKey,
          messages,
          signature: base64Decode(
            "iWIbLh10y1BkB6h+6ILXg6pJTKanCcE5C+IaRlxeNqk4GpygZywGxopHgnGD7KNUW8kT4rslyHoud5gML2luEiSqT0MsX63OTysfj2Y2nXM="
          ),
        };
        expect((await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.verify(verifyRequest)).verified).toBeFalsy();
      });

      it("should not verify when messages empty", async () => {
        const request: BbsBoundVerifyRequest = {
          publicKey: bbsKeyPair.publicKey,
          blsSecretKey: blsKeyPair.secretKey,
          messages: [],
          signature: base64Decode(
            "iWIbLh10y1BkB6h+6ILXg6pJTKanCcE5C+IaRlxeNqk4GpygZywGxopHgnGD7KNUW8kT4rslyHoud5gML2luEiSqT0MsX63OTysfj2Y2nXM="
          ),
        };
        expect((await bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.verify(request)).verified).toBeFalsy();
      });

      it("should not verify when public key invalid length", async () => {
        const request: BbsBoundVerifyRequest = {
          publicKey: new Uint8Array(20),
          blsSecretKey: blsKeyPair.secretKey,
          messages: [],
          signature: base64Decode(
            "iWIbLh10y1BkB6h+6ILXg6pJTKanCcE5C+IaRlxeNqk4GpygZywGxopHgnGD7KNUW8kT4rslyHoud5gML2luEiSqT0MsX63OTysfj2Y2nXM="
          ),
        };
        await expect(bbs_bound.bls12381_bbs_g1_bls_sig_g2_sha256.verify(request)).rejects.toThrowError(
          "Error: vector to fixed-sized array conversion failed"
        );
      });
    });
  });
});
