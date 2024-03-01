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
  readonly presentationHeader: string;
  result: { valid: false; reason: string } | { valid: true };
  readonly messages: string[];
  readonly disclosedIndexes: number[]; 
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

export const bls12381Sha256SignatureFixtures = fetchNestedFixtures<
  SignatureFixture
>("", resolveFixtures("bls12_381_sha_256/signature"));

export const bls12381Shake256SignatureFixtures = fetchNestedFixtures<
  SignatureFixture
>("", resolveFixtures("bls12_381_shake_256/signature"));

export const bls12381Sha256ProofFixtures = fetchNestedFixtures<ProofFixture>(
  "",
  resolveFixtures("bls12_381_sha_256/proof")
);

export const bls12381Shake256ProofFixtures = fetchNestedFixtures<ProofFixture>(
  "",
  resolveFixtures("bls12_381_shake_256/proof")
);

export { keyPair };
