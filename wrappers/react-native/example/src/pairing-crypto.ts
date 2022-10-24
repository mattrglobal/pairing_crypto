import R from 'ramda';
import { Buffer } from 'buffer';
import { BbsVerifyResult, bbs } from '@mattrglobal/pairing-crypto-rn';

import { FixtureItem, SignatureFixture, ProofFixture, fixtures } from '../__fixtures__';

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
  const revealedMessages = R.values(fixture.value.revealedMessages);
  const messages = fixtures.testAsset.value.messages.map((message) => ({
    value: convert.byteArrayFromHex(message),
    reveal: revealedMessages.includes(message),
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
    messages: messages.map((item) => item.value),
    header,
  });
  console.info('Generated signature', { signature: convert.byteArrayToHex(signature) });

  const proof = await bbs.bls12381_sha256.proofGen({
    verifySignature: true,
    publicKey: keyPair.publicKey,
    messages,
    signature,
    header,
    presentationHeader,
  });
  console.info('Generated proof', { proof: convert.byteArrayToHex(proof) });

  return await bbs.bls12381_sha256.proofVerify({
    publicKey: keyPair.publicKey,
    proof,
    header,
    presentationHeader,
    totalMessageCount: messages.length,
    messages: fixture.value.revealedMessages
      ? R.mapObjIndexed(convert.byteArrayFromHex, fixture.value.revealedMessages)
      : undefined,
  });
};

export const BbsBls12381Shake256ProofGen = async (fixture: FixtureItem<ProofFixture>): Promise<VerifyResult> => {
  const revealedMessages = R.values(fixture.value.revealedMessages);
  const messages = fixtures.testAsset.value.messages.map((message) => ({
    value: convert.byteArrayFromHex(message),
    reveal: revealedMessages.includes(message),
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
    messages: messages.map((item) => item.value),
    header,
  });
  console.info('Generated signature', { signature: convert.byteArrayToHex(signature) });

  const proof = await bbs.bls12381_shake256.proofGen({
    verifySignature: true,
    publicKey: keyPair.publicKey,
    messages,
    signature,
    header,
    presentationHeader,
  });
  console.info('Generated proof', { proof: convert.byteArrayToHex(proof) });

  return await bbs.bls12381_shake256.proofVerify({
    publicKey: keyPair.publicKey,
    proof,
    header,
    presentationHeader,
    totalMessageCount: messages.length,
    messages: fixture.value.revealedMessages
      ? R.mapObjIndexed(convert.byteArrayFromHex, fixture.value.revealedMessages)
      : undefined,
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
  return await bbs.bls12381_sha256.proofVerify({
    publicKey: convert.byteArrayFromHex(fixture.value.signerPublicKey),
    header: convert.byteArrayFromHex(fixture.value.header),
    presentationHeader: convert.byteArrayFromHex(fixture.value.presentationHeader),
    totalMessageCount: fixture.value.totalMessageCount,
    messages: fixture.value.revealedMessages
      ? R.mapObjIndexed(convert.byteArrayFromHex, fixture.value.revealedMessages)
      : undefined,
    proof: convert.byteArrayFromHex(fixture.value.proof),
  });
};

export const BbsBls12381Shake256ProofVerify = async (fixture: FixtureItem<ProofFixture>): Promise<BbsVerifyResult> => {
  return await bbs.bls12381_shake256.proofVerify({
    publicKey: convert.byteArrayFromHex(fixture.value.signerPublicKey),
    header: convert.byteArrayFromHex(fixture.value.header),
    presentationHeader: convert.byteArrayFromHex(fixture.value.presentationHeader),
    totalMessageCount: fixture.value.totalMessageCount,
    messages: fixture.value.revealedMessages
      ? R.mapObjIndexed(convert.byteArrayFromHex, fixture.value.revealedMessages)
      : undefined,
    proof: convert.byteArrayFromHex(fixture.value.proof),
  });
};
