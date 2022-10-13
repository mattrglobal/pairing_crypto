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
