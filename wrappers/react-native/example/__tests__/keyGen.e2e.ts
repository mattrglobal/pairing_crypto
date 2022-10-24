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
import { by, device, expect, element } from 'detox';

describe('keyGen', () => {
  beforeAll(async () => {
    await device.launchApp({ newInstance: true });
    await element(by.id('mainScrollView')).scrollTo('top');
  });

  it('should generate bls12_381_sha_256 key pair without error', async () => {
    await element(by.id('BbsBls12381Sha256GenerateKeyPair')).tap();
    await expect(element(by.id('BbsBls12381Sha256GenerateKeyPair-TestResult'))).toHaveText('Passed: true');
  });

  it('should generate bls12_381_shake_256 key pair without error', async () => {
    await element(by.id('BbsBls12381Shake256GenerateKeyPair')).tap();
    await expect(element(by.id('BbsBls12381Shake256GenerateKeyPair-TestResult'))).toHaveText('Passed: true');
  });
});
