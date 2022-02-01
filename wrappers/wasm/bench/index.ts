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

import { generateBbsSignRequest } from "./helper";

/* eslint-disable @typescript-eslint/camelcase */
import { report, benchmarkPromise } from "@stablelib/benchmark";
import { bls12381 } from "../lib/index";

// main benchmark routine
const runBbsBenchmark = async (
  numberOfMessages: number,
  messageSizeInBytes: number,
  numberRevealed: number
): Promise<void> => {
  const keyPair = await bls12381.generateG2KeyPair();

  const messageSignRequest = await generateBbsSignRequest(
    keyPair,
    numberOfMessages,
    messageSizeInBytes
  );
  const messageSignature = await bls12381.bbs.sign(messageSignRequest);
  const messageVerifyRequest = {
    signature: messageSignature,
    publicKey: keyPair.publicKey,
    messages: messageSignRequest.messages,
  };

  report(
    `BBS Sign ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
    await benchmarkPromise(() => bls12381.bbs.sign(messageSignRequest))
  );

  report(
    `BBS Verify ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
    await benchmarkPromise(() => bls12381.bbs.verify(messageVerifyRequest))
  );
};

(async () => {
  report(
    "BLS 12-381 Key Generation G2",
    await benchmarkPromise(() => bls12381.generateG2KeyPair())
  );

  report(
    "BLS 12-381 Key Generation G1",
    await benchmarkPromise(() => bls12381.generateG1KeyPair())
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
