import React, { forwardRef, useState, useImperativeHandle } from 'react';
import { Text, View, StyleSheet } from 'react-native';

import { inspect } from './utils';
import { Button } from './Button';
import { useTestReport } from './TestReport';
import type { TestCaseInstance } from './TestGroup';
import type { VerifyResult } from './pairing-crypto';
import type { FixtureItem } from '../__fixtures__';

export type TestFixtureProps = {
  readonly testID: string;
  readonly fixture: FixtureItem;
  readonly verify: () => Promise<VerifyResult>;
};

export const TestFixture = forwardRef<TestCaseInstance, TestFixtureProps>((props, ref) => {
  const { testID, fixture, verify } = props;
  const [hasError, setHasError] = useState<boolean>();
  const [isVerified, setIsVerified] = useState<boolean>();

  const reporter = useTestReport();

  const handlePress = async () => {
    try {
      const result = await verify();
      if (result.verified) {
        console.info('Verified fixture', inspect({ result, fixture }));
      } else {
        console.info('Invalid fixture', inspect({ result, fixture }));
      }
      setHasError(false);
      setIsVerified(result.verified);
      reporter.update({
        testID,
        result,
        passed: fixture.value.result.valid === result.verified,
      });
    } catch (error) {
      console.error('Failed to verify fixture', inspect({ fixture, error }));
      setHasError(true);
      setIsVerified(undefined);
      reporter.update({ testID, error, passed: false });
    }
  };
  useImperativeHandle(ref, () => ({ runTest: handlePress }));

  const isPassed = isVerified === fixture.value.result.valid;
  const expectStatus = fixture.value.result.valid ? 'T' : 'F';
  const resultStatus = hasError ? 'ERROR' : isVerified === undefined ? 'NONE' : isPassed ? 'PASS' : 'FAIL';

  return (
    <View testID={`${testID}-TestFixture`} style={styles.container}>
      <Button testID={testID} title={fixture.name} onPress={handlePress} />

      <Text style={styles.statusText}>Exp: {expectStatus}</Text>
      <Text style={styles.statusText}>Res: {resultStatus}</Text>
    </View>
  );
});

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    justifyContent: 'center',
  },
  statusText: {
    fontVariant: ['tabular-nums'],
    marginLeft: 8,
  },
});
