import { fixtures } from './fixtures.ts';

import { Buffer } from 'buffer';
import { bbs, BbsVerifyResult } from '@mattrglobal/pairing-crypto-rn';

// TODO need to generalize for other cipher suite
export const executeSignatureFixtures = async (): Promise<{
  successful: boolean;
  failures: string[];
}> => {
  const results = await Promise.all(
    [fixtures.bls12381Shake256SignatureFixtures[8]].map(
      async (
        item: SignatureFixture,
        _: number,
        __: readonly SignatureFixture[]
      ) => {
        return {
          fixture: item,
          verificationResult: await bbs.bls12381_shake256.verify({
            publicKey: new Uint8Array(
              Buffer.from(item.value.signerKeyPair.publicKey, 'hex')
            ),
            header: new Uint8Array(Buffer.from(item.value.header, 'hex')),
            signature: new Uint8Array(Buffer.from(item.value.signature, 'hex')),
            messages: item.value.messages.map(
              (item) => new Uint8Array(Buffer.from(item, 'hex'))
            ),
          }),
        };
      },
      [] as Promise<{
        fixture: SignatureFixture;
        verificationResult: BbsVerifyResult;
      }>[]
    )
  );

  console.log(JSON.stringify(results, null, 2));

  const failedFixtures = results
    .filter(
      (item) =>
        item.fixture.value.result.valid !== item.verificationResult.verified
    )
    .map((item) => item.fixture.name);

  return {
    successful: failedFixtures.length == 0,
    failures: failedFixtures,
  };
};

// TODO
export const executeProofFixtures = async (): Promise<{
  successful: boolean;
  failures: string[];
}> => {
  const results = await Promise.all(
    fixtures.bls12381Shake256SignatureFixtures.map(
      async (
        item: SignatureFixture,
        _: number,
        __: readonly SignatureFixture[]
      ) => {
        return {
          fixture: item,
          verificationResult: await bbs.bls12381_shake256.proofVerify({
            publicKey: new Uint8Array(
              Buffer.from(item.value.signerKeyPair.publicKey, 'hex')
            ),
            header: new Uint8Array(Buffer.from(item.value.header, 'hex')),
            signature: new Uint8Array(Buffer.from(item.value.signature, 'hex')),
            messages: item.value.messages.map(
              (item) => new Uint8Array(Buffer.from(item, 'hex'))
            ),
          }),
        };
      },
      [] as Promise<{
        fixture: SignatureFixture;
        verificationResult: BbsVerifyResult;
      }>[]
    )
  );

  console.log(JSON.stringify(results, null, 2));

  const failedFixtures = results
    .filter(
      (item) =>
        item.fixture.value.result.valid !== item.verificationResult.verified
    )
    .map((item) => item.fixture.name);

  return {
    successful: failedFixtures.length == 0,
    failures: failedFixtures,
  };
};
