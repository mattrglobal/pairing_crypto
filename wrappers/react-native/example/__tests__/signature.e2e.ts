import R from 'ramda';
import { by, device, expect, element } from 'detox';

import { FixtureItem, fixtures } from '../__fixtures__';

describe('signature', () => {
  beforeAll(async () => {
    await device.launchApp({ newInstance: true });
    await element(by.id('mainScrollView')).scrollTo('top');
  });

  const runFixtureTest = (category: string) => async (_: string, fixture: FixtureItem) => {
    const testID = `${fixture.source}-${category}`;
    const testReportID = `${testID}-TestReport`;
    const testResultID = `${testID}-TestResult`;

    await waitFor(element(by.id(testID)))
      .toBeVisible()
      .whileElement(by.id('mainScrollView'))
      .scroll(250, 'down');

    // execute test case
    await element(by.id(testID)).tap();

    // wait for async operation to complete
    await waitFor(element(by.id(testReportID)))
      .toBeVisible()
      .withTimeout(2000);

    await expect(element(by.id(testResultID))).toHaveText('Passed: true');
  };

  it.each(R.values(fixtures.bls12381Sha256Signature).map((fixture) => [fixture.name, fixture] as const))(
    'should verify bls12_381_sha_256 signature: %s',
    runFixtureTest('SignatureVerify')
  );

  it.each(R.values(fixtures.bls12381Shake256Signature).map((fixture) => [fixture.name, fixture] as const))(
    'should verify bls12_381_shake_256 signature: %s',
    runFixtureTest('SignatureVerify')
  );

  it.each(R.values(fixtures.bls12381Sha256Proof).map((fixture) => [fixture.name, fixture] as const))(
    'should verify bls12_381_sha_256 proof: %s',
    runFixtureTest('ProofVerify')
  );

  it.each(R.values(fixtures.bls12381Shake256Proof).map((fixture) => [fixture.name, fixture] as const))(
    'should verify bls12_381_shake_256 proof: %s',
    runFixtureTest('ProofVerify')
  );

  it.each(R.values(fixtures.bls12381Sha256ProofValidCases).map((fixture) => [fixture.name, fixture] as const))(
    'should verify bls12_381_sha_256 proof: %s',
    runFixtureTest('ProofGen')
  );

  it.each(R.values(fixtures.bls12381Shake256ProofValidCases).map((fixture) => [fixture.name, fixture] as const))(
    'should verify bls12_381_shake_256 proof: %s',
    runFixtureTest('ProofGen')
  );
});
