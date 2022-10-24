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
import * as R from 'ramda';

/**
 * Fixture data sets are injected via Babel plugin, folder structure will be preserved.
 */
const FIXTURES = process.env.__FIXTURES__ as any; // eslint-disable-line @typescript-eslint/no-explicit-any

export type Fixture = ProofFixture | SignatureFixture;

export type Fixtures<T = Fixture> = Record<string, FixtureItem<T>>;
export type FixtureItem<T = Fixture> = {
  readonly source: string;
  readonly name: string;
  readonly value: T;
};

export interface TestAsset {
  readonly keyIkm: string;
  readonly spareKeyIkm: string;
  readonly keyInfo: string;
  readonly header: string;
  readonly presentationHeader: string;
  readonly messages: string[];
}

export interface ProofFixture {
  readonly caseName: string;
  readonly proof: string;
  readonly header: string;
  readonly presentationHeader: string;
  readonly totalMessageCount: number;
  readonly result: { valid: false; reason: string } | { valid: true };
  readonly revealedMessages: { [key: number]: string };
  readonly signerPublicKey: string;
}

export interface SignatureFixture {
  readonly caseName: string;
  readonly signature: string;
  readonly header: string;
  readonly messages: string[];
  readonly result: { valid: false; reason: string } | { valid: true };
  readonly signerKeyPair: {
    readonly publicKey: string;
    readonly secretKey: string;
  };
}

const resolve = <T>(path: string): T => {
  const value = R.path(path.split('/'), FIXTURES) as T;
  if (!value) {
    throw new Error(`No fixtures found at ${path}`);
  }
  return value;
};

const testAsset = resolve<FixtureItem<TestAsset>>('test_asset');

const bls12381Sha256Signature = resolve<Fixtures<SignatureFixture>>('bls12_381_sha_256/signature');
const bls12381Shake256Signature = resolve<Fixtures<SignatureFixture>>('bls12_381_shake_256/signature');
const bls12381Sha256Proof = resolve<Fixtures<ProofFixture>>('bls12_381_sha_256/proof');
const bls12381Shake256Proof = resolve<Fixtures<ProofFixture>>('bls12_381_shake_256/proof');

export const fixtures = {
  testAsset,

  bls12381Sha256Signature,
  bls12381Shake256Signature,
  bls12381Sha256Proof,
  bls12381Shake256Proof,

  bls12381Sha256ProofValidCases: R.pipe(
    R.mapObjIndexed((item: FixtureItem<ProofFixture>) => (item.value.result.valid ? item : undefined)),
    R.reject(R.isNil)
  )(bls12381Sha256Proof),

  bls12381Shake256ProofValidCases: R.pipe(
    R.mapObjIndexed((item: FixtureItem<ProofFixture>) => (item.value.result.valid ? item : undefined)),
    R.reject(R.isNil)
  )(bls12381Shake256Proof),
};
