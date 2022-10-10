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

interface BbsVerifyProofMessageRequest {
  /**
   * Messages that was signed to produce the signature
   */
  readonly [key: number]: Uint8Array;
}

/**
 * A request to verify a BBS signature proof of knowledge for a set of messages
 */
export interface BbsVerifyProofRequest {
  /**
   * Public key of the signer of the signature
   */
  readonly publicKey: Uint8Array;
  /**
   * Header message that was included in the proof
   */
  readonly header?: Uint8Array;
  /**
   * Presentation header that was included in the proof
   */
  readonly presentationHeader?: Uint8Array;
  /**
   * The total number of messages that were originally signed by the underlying signature
   */
  readonly totalMessageCount: number;
  /**
   * Raw proof value
   */
  readonly proof: Uint8Array;
  /**
   * Revealed messages
   */
  readonly messages?: BbsVerifyProofMessageRequest;
}
