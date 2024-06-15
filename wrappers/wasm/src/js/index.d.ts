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
  KeyPair,
  KeyGenerationRequest,
} from "./types";

import {
  BbsSignRequest,
  BbsVerifyRequest,
  BbsVerifyResult,
  BbsDeriveProofRequest,
  BbsVerifyProofRequest,
} from "./types/bbs";

import {
  BlsKeyPopGenRequest,
  BlsKeyPopVerifyRequest,
  BbsBoundSignRequest,
  BbsBoundVerifyRequest,
  BbsBoundVerifyResult,
  BbsBoundDeriveProofRequest,
  BbsBoundVerifyProofRequest,
} from "./types/bbs_bound";

export * from "./types";
export * from "./types/bbs";
export * from "./types/bbs_bound";

export namespace bbs {
  namespace bls12381_sha256 {
    const PRIVATE_KEY_LENGTH = 32;
    const PUBLIC_KEY_LENGTH = 96;
    const SIGNATURE_LENGTH = 90;

    function generateKeyPair(
      request?: KeyGenerationRequest
    ): Promise<Required<KeyPair>>;
    function generateKeyPairUncompressed(
      request?: KeyGenerationRequest
    ): Promise<Required<KeyPair>>;
    function sign(request: BbsSignRequest): Promise<Uint8Array>;
    function verify(request: BbsVerifyRequest): Promise<BbsVerifyResult>;
    function deriveProof(request: BbsDeriveProofRequest): Promise<Uint8Array>;
    function verifyProof(
      request: BbsVerifyProofRequest
    ): Promise<BbsVerifyResult>;
  }

  namespace bls12381_shake256 {
    const PRIVATE_KEY_LENGTH = 32;
    const PUBLIC_KEY_LENGTH = 96;
    const SIGNATURE_LENGTH = 80;

    function generateKeyPair(
      request?: KeyGenerationRequest
    ): Promise<Required<KeyPair>>;
    function generateKeyPairUncompressed(
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

export namespace bbs_bound {
  namespace bls12381_bbs_g1_bls_sig_g2_sha256 {
    const BBS_PRIVATE_KEY_LENGTH = 32;
    const BBS_PUBLIC_KEY_LENGTH = 96;
    const BBS_SIGNATURE_LENGTH = 80;
    const BLS_PRIVATE_KEY_LENGTH = 32;
    const BLS_PUBLIC_KEY_LENGTH = 96;
    const BLS_KEY_POP_LENGTH = 96;

    function generateBbsKeyPair(
      request?: KeyGenerationRequest
    ): Promise<Required<KeyPair>>;
    function generateBlsKeyPair(
      request?: KeyGenerationRequest
    ): Promise<Required<KeyPair>>;
    function blsKeyPopGen(request: BlsKeyPopGenRequest): Promise<Uint8Array>;
    function blsKeyPopVerify(request: BlsKeyPopVerifyRequest): Promise<BbsBoundVerifyResult>;
    function sign(request: BbsBoundSignRequest): Promise<Uint8Array>;
    function verify(request: BbsBoundVerifyRequest): Promise<BbsBoundVerifyResult>;
    function deriveProof(request: BbsBoundDeriveProofRequest): Promise<Uint8Array>;
    function verifyProof(
      request: BbsBoundVerifyProofRequest
    ): Promise<BbsBoundVerifyResult>;
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

  function compressedToUncompressedPublicKey(
    request?: Uint8Array
  ): Promise<Uint8Array>;

  function uncompressedToCompressedPublicKey(
    request?: Uint8Array
  ): Promise<Uint8Array>;
}
