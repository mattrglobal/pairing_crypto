import React, { forwardRef, useRef, useState, useImperativeHandle } from 'react';
import { Text, View, StyleSheet } from 'react-native';

import { inspect } from './utils';
import { Button } from './Button';
import { useTestReport } from './TestReport';
import type { VerifyResult } from './pairing-crypto';
import type { FixtureItem } from '../__fixtures__';

export type TestSignatureProps = {
  readonly testID: string;
  readonly fixture: FixtureItem;
  readonly verify: () => Promise<VerifyResult>;
};

export type TestSignatureInstance = {
  readonly runTest: () => Promise<void>;
};

export const TestSignature = forwardRef<TestSignatureInstance, TestSignatureProps>((props, ref) => {
  const { testID, fixture, verify } = props;
  const [hasError, setHasError] = useState<boolean>();
  const [isVerified, setIsVerified] = useState<boolean>();

  const reporter = useTestReport();

  const handlePress = async () => {
    try {
      const result = await verify();
      if (result.verified) {
        console.info('Verified signature', inspect({ result, fixture }));
      } else {
        console.info('Invalid signature', inspect({ result, fixture }));
      }
      setHasError(false);
      setIsVerified(result.verified);
      reporter.update({
        testID,
        result,
        passed: fixture.value.result.valid === result.verified,
      });
    } catch (error) {
      console.error('Failed to verify signature', inspect({ fixture, error }));
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
    <View testID={`${testID}-TestSignature`} style={styles.container}>
      <Button testID={testID} title={fixture.name} onPress={handlePress} />

      <Text style={styles.statusText}>Exp: {expectStatus}</Text>
      <Text style={styles.statusText}>Res: {resultStatus}</Text>
    </View>
  );
});

export type TestSignatureControlProps = {
  readonly register: (fixture: FixtureItem) => (instance: TestSignatureInstance | null) => void;
  readonly verifyAll: () => Promise<void>;
};
export const useTestSignatureControl = (): TestSignatureControlProps => {
  const instancesRef = useRef(new Map<string, TestSignatureInstance>());

  const register = (fixture: FixtureItem) => (instance: TestSignatureInstance | null) => {
    if (!instance) {
      instancesRef.current.delete(fixture.source);
    } else {
      instancesRef.current.set(fixture.source, instance);
    }
  };

  const verifyAll = async (): Promise<void> => {
    for (const instance of Array.from(instancesRef.current.values())) {
      await instance.runTest();
    }
  };

  return { register, verifyAll };
};

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
