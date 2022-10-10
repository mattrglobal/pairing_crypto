/*!
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

const { writeFileSync, readFileSync } = require('fs');

// can't use opecore isObject, getting error: Maximum call stack size exceeded
const isObject = (value: unknown) => value && typeof value === 'object';

// tslint:disable-next-line:no-var-requires
const resolveFixtures = (subDirectory: string) =>
  require('require-all')({
    dirname: `${__dirname}/../../../../tests/fixtures/bbs/${subDirectory}`,
    filter: /.json$/,
    excludeDirs: ['.github', 'tests'],
    map: (__: unknown, path: unknown) => {
      return `${path}`;
    },
  });

interface ProofFixtureData {
  readonly caseName: string;
  readonly proof: string;
  readonly header: string;
  readonly presentationHeader: string;
  readonly totalMessageCount: number;
  result: { valid: false; reason: string } | { valid: true };
  readonly revealedMessages: { [key: number]: string };
  readonly signerPublicKey: string;
}

interface SignatureFixtureData {
  readonly caseName: string;
  readonly signature: string;
  readonly header: string;
  readonly messages: string[];
  result: { valid: false; reason: string } | { valid: true };
  readonly signerKeyPair: {
    readonly publicKey: string;
    readonly secretKey: string;
  };
}

interface ProofFixture {
  readonly name: string;
  readonly value: ProofFixtureData;
}

interface SignatureFixture {
  readonly name: string;
  readonly value: SignatureFixtureData;
}

const fetchNestedFixtures = <T>(name: string, input: any): ReadonlyArray<T> => {
  if (input.caseName) {
    return [{ name, value: input } as any];
  }
  if (!isObject(input)) {
    return [];
  }

  const extractedFixtures = Object.keys(input).map((key) =>
    fetchNestedFixtures(key, input[key])
  );
  return Array.prototype.concat.apply([], extractedFixtures);
};

const bls12381Sha256SignatureFixtures = fetchNestedFixtures<SignatureFixture>(
  '',
  resolveFixtures('bls12_381_sha_256/signature')
);

const bls12381Shake256SignatureFixtures = fetchNestedFixtures<SignatureFixture>(
  '',
  resolveFixtures('bls12_381_shake_256/signature')
);

const bls12381Sha256ProofFixtures = fetchNestedFixtures<ProofFixture>(
  '',
  resolveFixtures('bls12_381_sha_256/proof')
);

const bls12381Shake256ProofFixtures = fetchNestedFixtures<ProofFixture>(
  '',
  resolveFixtures('bls12_381_shake_256/proof')
);

const updateFixtureFile = () => {
  const keyPair = JSON.parse(
    readFileSync(`${__dirname}/keyPair.json`).toString()
  );

  const fixtures = {
    keyPair,
    bls12381Sha256SignatureFixtures,
    bls12381Shake256SignatureFixtures,
    bls12381Sha256ProofFixtures,
    bls12381Shake256ProofFixtures,
  };

  writeFileSync(
    `${__dirname}/../src/fixtures.ts`,
    `export const fixtures = ${JSON.stringify(fixtures, null, 2)} as any;`
  );
};

updateFixtureFile();
