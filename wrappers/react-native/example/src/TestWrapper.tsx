import React, { forwardRef, useImperativeHandle } from 'react';
import type { ButtonProps } from 'react-native';

import { inspect } from './utils';
import { Button } from './Button';
import { useTestReport } from './TestReport';
import type { VerifyResult } from './pairing-crypto';
import type { TestCaseInstance } from './TestGroup';

export type TestWrapperProps = ButtonProps & {
  readonly testID: string;
  readonly fixture?: unknown;
  readonly verify: () => Promise<VerifyResult>;
};

export const TestWrapper = forwardRef<TestCaseInstance, TestWrapperProps>((props, ref) => {
  const { testID, fixture, verify, ...buttonProps } = props;

  const reporter = useTestReport();

  const handlePress = async () => {
    try {
      const result = await verify();
      if (result.verified) {
        console.info('Verified', inspect({ fixture, result }));
      } else {
        console.info('Verification failed', inspect({ fixture, result }));
      }
      reporter.update({ testID, result, passed: result.verified });
    } catch (error) {
      console.error('Error verifying test case', inspect({ fixture, error }));
      reporter.update({ testID, error, passed: false });
    }
  };
  useImperativeHandle(ref, () => ({ runTest: handlePress }));

  return <Button {...buttonProps} testID={testID} onPress={handlePress} />;
});
