/*!
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import * as keyPair from "./keyPair.json";

// can't use opecore isObject, getting error: Maximum call stack size exceeded
const isObject = (value: unknown) => value && typeof value === "object";

// tslint:disable-next-line:no-var-requires
const resolveFixtures = (subDirectory: string) =>
  require("require-all")({
    dirname: `${__dirname}/../../../tests/fixtures/bbs/${subDirectory}`,
    filter: /.json$/,
    excludeDirs: [".github", "tests"],
    map: (__: unknown, path: unknown) => {
      return `${path}`;
    },
  });

export interface ProofFixtureData {
  readonly caseName: string;
  readonly proof: string;
  readonly header: string;
  readonly presentationMessage: string;
  readonly totalMessageCount: number;
  result: { valid: false; reason: string } | { valid: true };
  readonly revealedMessages: { [key: number]: string };
  readonly signerPublicKey: string;
}

export interface SignatureFixtureData {
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

export interface ProofFixture {
  readonly name: string;
  readonly value: ProofFixtureData;
}

export interface SignatureFixture {
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

export const signatureFixtures = fetchNestedFixtures<SignatureFixture>(
  "",
  resolveFixtures("signature")
);

export const proofFixtures = fetchNestedFixtures<ProofFixture>(
  "",
  resolveFixtures("proof")
);

export { keyPair };
