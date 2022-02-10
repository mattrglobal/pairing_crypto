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
  BbsSignRequest,
  BbsVerifyRequest,
  BbsVerifyResult,
  KeyPair,
  BbsDeriveProofRequest,
  BbsVerifyProofRequest,
} from "./types";

export * from "./types";

export namespace bls12381 {
  const PRIVATE_KEY_LENGTH = 32;
  const G1_PUBLIC_KEY_LENGTH = 48;
  const G2_PUBLIC_KEY_LENGTH = 96;

  function generateG1KeyPair(seed?: Uint8Array): Promise<Required<KeyPair>>;
  function generateG2KeyPair(seed?: Uint8Array): Promise<Required<KeyPair>>;

  namespace bbs {
    const SIGNATURE_LENGTH = 112;
    const SIGNER_PUBLIC_KEY_LENGTH = 96;

    function sign(request: BbsSignRequest): Promise<Uint8Array>;
    function verify(request: BbsVerifyRequest): Promise<BbsVerifyResult>;
    function deriveProof(request: BbsDeriveProofRequest): Promise<Uint8Array>;
    function verifyProof(request: BbsVerifyProofRequest): Promise<boolean>;
  }
}
