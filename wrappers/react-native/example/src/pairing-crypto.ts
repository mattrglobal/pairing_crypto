/*
 * Copyright 2022 - MATTR Limited
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
import R from 'ramda';
import { Buffer } from 'buffer';
import { BbsVerifyResult, bbs } from '@mattrglobal/pairing-crypto-rn';

import { FixtureItem, SignatureFixture, ProofFixture, fixtures } from '../__fixtures__';

// Helper type for revealed messages
type revealedMessages = { [k: number]: Uint8Array };

// Utility functions
const utils = {
  toRevealedMessages: (signedMessages: Uint8Array[], disclosedIndexes: number[]): revealedMessages | undefined => {
    const accumulator: revealedMessages = {};

    function appender(acc: { [k: number]: Uint8Array }, idx: number): [{ [k: number]: Uint8Array }, number] {
      if (signedMessages[idx]) {
        acc[idx] = signedMessages[idx];
      }
      return [acc, idx];
    }

    return disclosedIndexes ? R.mapAccum(appender, accumulator, disclosedIndexes)[0] : undefined;
  },
};

export interface VerifyResult {
  readonly verified: boolean;
  readonly error?: Error;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly [key: string]: any;
}

const convert = {
  byteArrayToHex: (data: Uint8Array): string => Buffer.from(data).toString('hex'),
  byteArrayFromHex: (data: string): Uint8Array => new Uint8Array(Buffer.from(data, 'hex')),
};

export const BbsBls12381Sha256GenerateKeyPair = async (): Promise<VerifyResult> => {
  const keyPair = await bbs.bls12381_sha256.generateKeyPair();
  if (!keyPair) {
    return {
      verified: false,
      error: new Error('Expected key pair, but undefined'),
    };
  }
  return { verified: true, keyPair };
};

export const BbsBls12381Shake256GenerateKeyPair = async (): Promise<VerifyResult> => {
  const keyPair = await bbs.bls12381_shake256.generateKeyPair();
  if (!keyPair) {
    return {
      verified: false,
      error: new Error('Expected key pair, but undefined'),
    };
  }
  return { verified: true, keyPair };
};

export const BbsBls12381Sha256ProofGen = async (fixture: FixtureItem<ProofFixture>): Promise<VerifyResult> => {
  const signedMessages: Uint8Array[] = fixture.value.messages.map((message) => convert.byteArrayFromHex(message));
  const disclosedIndexes: number[] = fixture.value.disclosedIndexes;
  const messages = signedMessages.map((message, idx) => ({
    value: message,
    reveal: disclosedIndexes.includes(idx),
  }));

  const header = convert.byteArrayFromHex(fixtures.testAsset.value.header);
  const presentationHeader = convert.byteArrayFromHex(fixtures.testAsset.value.presentationHeader);

  const keyPair = await bbs.bls12381_sha256.generateKeyPair({
    ikm: convert.byteArrayFromHex(fixtures.testAsset.value.keyIkm),
    keyInfo: convert.byteArrayFromHex(fixtures.testAsset.value.keyInfo),
  });
  console.info('Generated key pair', { keyPair });

  const signature = await bbs.bls12381_sha256.sign({
    secretKey: keyPair.secretKey,
    publicKey: keyPair.publicKey,
    messages: signedMessages,
    header,
  });
  console.info('Generated signature', { signature: convert.byteArrayToHex(signature) });

  const proof = await bbs.bls12381_sha256.deriveProof({
    verifySignature: true,
    publicKey: keyPair.publicKey,
    messages,
    signature,
    header,
    presentationHeader,
  });
  console.info('Generated proof', { proof: convert.byteArrayToHex(proof) });

  return await bbs.bls12381_sha256.verifyProof({
    publicKey: keyPair.publicKey,
    proof,
    header,
    presentationHeader,
    messages: utils.toRevealedMessages(signedMessages, disclosedIndexes),
  });
};

export const BbsBls12381Shake256ProofGen = async (fixture: FixtureItem<ProofFixture>): Promise<VerifyResult> => {
  const signedMessages: Uint8Array[] = fixture.value.messages.map((message) => convert.byteArrayFromHex(message));
  const disclosedIndexes: number[] = fixture.value.disclosedIndexes;
  const messages = signedMessages.map((message, idx) => ({
    value: message,
    reveal: disclosedIndexes.includes(idx),
  }));

  const header = convert.byteArrayFromHex(fixtures.testAsset.value.header);
  const presentationHeader = convert.byteArrayFromHex(fixtures.testAsset.value.presentationHeader);

  const keyPair = await bbs.bls12381_shake256.generateKeyPair({
    ikm: convert.byteArrayFromHex(fixtures.testAsset.value.keyIkm),
    keyInfo: convert.byteArrayFromHex(fixtures.testAsset.value.keyInfo),
  });
  console.info('Generated key pair', { keyPair });

  const signature = await bbs.bls12381_shake256.sign({
    secretKey: keyPair.secretKey,
    publicKey: keyPair.publicKey,
    messages: signedMessages,
    header,
  });
  console.info('Generated signature', { signature: convert.byteArrayToHex(signature) });

  const proof = await bbs.bls12381_shake256.deriveProof({
    verifySignature: true,
    publicKey: keyPair.publicKey,
    messages,
    signature,
    header,
    presentationHeader,
  });
  console.info('Generated proof', { proof: convert.byteArrayToHex(proof) });

  return await bbs.bls12381_shake256.verifyProof({
    publicKey: keyPair.publicKey,
    proof,
    header,
    presentationHeader,
    messages: utils.toRevealedMessages(signedMessages, disclosedIndexes),
  });
};

export const BbsBls12381Sha256Verify = async (fixture: FixtureItem<SignatureFixture>): Promise<BbsVerifyResult> => {
  return await bbs.bls12381_sha256.verify({
    publicKey: convert.byteArrayFromHex(fixture.value.signerKeyPair.publicKey),
    header: convert.byteArrayFromHex(fixture.value.header),
    signature: convert.byteArrayFromHex(fixture.value.signature),
    messages: fixture.value.messages.map(convert.byteArrayFromHex),
  });
};

export const BbsBls12381Shake256Verify = async (fixture: FixtureItem<SignatureFixture>): Promise<BbsVerifyResult> => {
  return await bbs.bls12381_shake256.verify({
    publicKey: convert.byteArrayFromHex(fixture.value.signerKeyPair.publicKey),
    header: convert.byteArrayFromHex(fixture.value.header),
    signature: convert.byteArrayFromHex(fixture.value.signature),
    messages: fixture.value.messages.map(convert.byteArrayFromHex),
  });
};

export const BbsBls12381Sha256ProofVerify = async (fixture: FixtureItem<ProofFixture>): Promise<BbsVerifyResult> => {
  return await bbs.bls12381_sha256.verifyProof({
    publicKey: convert.byteArrayFromHex(fixture.value.signerPublicKey),
    header: convert.byteArrayFromHex(fixture.value.header),
    presentationHeader: convert.byteArrayFromHex(fixture.value.presentationHeader),
    messages: utils.toRevealedMessages(
      R.map(convert.byteArrayFromHex, fixture.value.messages),
      fixture.value.disclosedIndexes
    ),
    proof: convert.byteArrayFromHex(fixture.value.proof),
  });
};

export const BbsBls12381Shake256ProofVerify = async (fixture: FixtureItem<ProofFixture>): Promise<BbsVerifyResult> => {
  return await bbs.bls12381_shake256.verifyProof({
    publicKey: convert.byteArrayFromHex(fixture.value.signerPublicKey),
    header: convert.byteArrayFromHex(fixture.value.header),
    presentationHeader: convert.byteArrayFromHex(fixture.value.presentationHeader),
    messages: utils.toRevealedMessages(
      R.map(convert.byteArrayFromHex, fixture.value.messages),
      fixture.value.disclosedIndexes
    ),
    proof: convert.byteArrayFromHex(fixture.value.proof),
  });
};
