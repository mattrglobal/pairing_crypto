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

interface BbsDeriveProofMessageRequest {
  /**
   * Messages that was signed to produce the signature
   */
  readonly value: Uint8Array;
  /**
   * Indicates whether to reveal the particular message in the derived proof
   */
  readonly reveal: boolean;
}

/**
 * A request to derive a BBS signature proof of knowledge for a signature and a set of messages
 */
export interface BbsDeriveProofRequest {
  /**
   * Public key of the signer of the signature
   */
  readonly publicKey: Uint8Array;
  /**
   * Header message to include in the derived proof
   */
  readonly header?: Uint8Array;
  /**
   * Presentation header to include in the derived proof
   */
  readonly presentationHeader?: Uint8Array;
  /**
   * Raw signature value
   */
  readonly signature: Uint8Array;
  /**
   * Messages that were signed to produce the signature
   */
  readonly messages?: readonly BbsDeriveProofMessageRequest[];
}
