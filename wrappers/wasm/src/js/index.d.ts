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
  KeyGenerationRequest,
} from "./types";

export * from "./types";

export namespace bbs {
  namespace bls12381 {
    const PRIVATE_KEY_LENGTH = 32;
    const PUBLIC_KEY_LENGTH = 96;
    const SIGNATURE_LENGTH = 112;

    function generateKeyPair(
      request?: KeyGenerationRequest
    ): Promise<Required<KeyPair>>;
    function sign(request: BbsSignRequest): Promise<Uint8Array>;
    function verify(request: BbsVerifyRequest): Promise<BbsVerifyResult>;
    function deriveProof(request: BbsDeriveProofRequest): Promise<Uint8Array>;
    function verifyProof(
      request: BbsVerifyProofRequest
    ): Promise<BbsVerifyResult>;
  }
}

export namespace utilities {
  function convertToRevealMessageArray(
    messages: Uint8Array[],
    revealedIndicies: number[]
  ): { value: Uint8Array; reveal: boolean }[];

  function convertRevealMessageArrayToRevealMap(
    messages: { value: Uint8Array; reveal: boolean }[]
  ): { [key: number]: Uint8Array };
}
