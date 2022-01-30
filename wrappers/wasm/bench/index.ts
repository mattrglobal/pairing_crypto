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

/* eslint-disable @typescript-eslint/camelcase */
const { benchmark, report, benchmarkPromise } = require("@stablelib/benchmark");
const { bls12381GenerateG1KeyPair, bls12381GenerateG2KeyPair } = require("../lib");

(async () => {
  report(
    "BLS 12-381 Key Generation G2",
    await benchmarkPromise(() => bls12381GenerateG2KeyPair()));

  report(
    "BLS 12-381 Key Generation G1",
    await benchmarkPromise(() => bls12381GenerateG1KeyPair())
  );
})();
