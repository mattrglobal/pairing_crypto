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

import { generateMessages } from "./helper";

/* eslint-disable @typescript-eslint/camelcase */
import { report, benchmarkPromise } from "@stablelib/benchmark";
import {
  BbsDeriveProofRequest,
  BbsSignRequest,
  BbsVerifyProofRequest,
  bbs,
  utilities,
} from "../lib/index";
import { randomBytes } from "@stablelib/random";

// main benchmark routine
const runBbsBenchmark = async (
  numberOfMessages: number,
  messageSizeInBytes: number,
  numberRevealed: number
): Promise<void> => {
  const keyPair = await bbs.bls12381.generateKeyPair({
    ikm: randomBytes(32),
    keyInfo: randomBytes(32),
  });
  const messages = generateMessages(numberOfMessages, messageSizeInBytes);
  const header = randomBytes(50);

  const messageSignRequest: BbsSignRequest = {
    secretKey: keyPair.secretKey,
    publicKey: keyPair.publicKey,
    header,
    messages,
  };

  const messageSignature = await bbs.bls12381.sign(messageSignRequest);

  const messageVerifyRequest = {
    signature: messageSignature,
    publicKey: keyPair.publicKey,
    header,
    messages,
  };

  const messagesToReveal = utilities.convertToRevealMessageArray(
    Array.from(messages),
    [...Array(numberRevealed).keys()]
  );

  const presentationMessage = randomBytes(32);

  const messageDeriveProof: BbsDeriveProofRequest = {
    signature: messageSignature,
    publicKey: keyPair.publicKey,
    header,
    messages: messagesToReveal,
    presentationMessage,
  };

  const proof = await bbs.bls12381.deriveProof(messageDeriveProof);

  const verifyProofRequest: BbsVerifyProofRequest = {
    proof,
    publicKey: keyPair.publicKey,
    header,
    messages: utilities.convertRevealMessageArrayToRevealMap(messagesToReveal),
    totalMessageCount: messages.length,
    presentationMessage,
  };

  report(
    `BBS Sign ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
    await benchmarkPromise(() => bbs.bls12381.sign(messageSignRequest))
  );

  report(
    `BBS Verify ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
    await benchmarkPromise(() => bbs.bls12381.verify(messageVerifyRequest))
  );

  report(
    `BBS Derive Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
    await benchmarkPromise(() => bbs.bls12381.deriveProof(messageDeriveProof))
  );

  report(
    `BBS Verify Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
    await benchmarkPromise(() => bbs.bls12381.verifyProof(verifyProofRequest))
  );
};

(async () => {
  report(
    "BBS Key Generation",
    await benchmarkPromise(() =>
      bbs.bls12381.generateKeyPair({
        ikm: randomBytes(32),
        keyInfo: randomBytes(32),
      })
    )
  );

  // ------------------------------ 1, 100 byte message ------------------------------
  await runBbsBenchmark(1, 100, 1);

  // ------------------------------ 1, 1000 byte message ------------------------------
  await runBbsBenchmark(1, 1000, 1);

  // ------------------------------ 10, 100 byte messages ------------------------------
  await runBbsBenchmark(10, 100, 1);

  // ------------------------------ 10, 1000 byte messages ------------------------------
  await runBbsBenchmark(10, 1000, 1);

  // ------------------------------ 100, 100 byte messages ------------------------------
  await runBbsBenchmark(100, 100, 1);

  // ------------------------------ 100, 1000 byte messages ------------------------------
  await runBbsBenchmark(100, 1000, 1);

  // ------------------------------ 100, 100 byte messages ------------------------------
  await runBbsBenchmark(100, 100, 50);

  // ------------------------------ 100, 1000 byte messages ------------------------------
  await runBbsBenchmark(100, 1000, 60);
})();
