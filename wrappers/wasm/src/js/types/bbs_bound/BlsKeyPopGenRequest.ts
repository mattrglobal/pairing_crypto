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

/**
 * A request to generate a proof of posession for holder's BLS secret key
 */
export interface BlsKeyPopGenRequest {
  /**
   * BLS secret key of the holder
   */
  readonly blsSecretKey: Uint8Array;
  /**
   * Unique identifier of the issuer
   */
  readonly aud: Uint8Array;
  /**
   * Domain separation tag
   */
  readonly dst?: Uint8Array;
  /**
   * Extra information to bind to a KeyPoP (e.g., creation date, dst etc.)
   */
  readonly extraInfo?: Uint8Array;
}
