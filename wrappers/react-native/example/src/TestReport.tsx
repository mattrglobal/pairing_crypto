import React, { forwardRef, createContext, useContext, useState, useRef, useImperativeHandle } from 'react';
import { SafeAreaView, Text, View, StyleSheet } from 'react-native';
import { Colors } from 'react-native/Libraries/NewAppScreen';

import { inspect } from './utils';

type TestReport = {
  readonly testID: string;
  readonly passed: boolean;
  readonly error?: unknown;
  readonly result?: unknown;
};

type TestReportInstance = {
  readonly update: (next: TestReport) => void;
};

export const TestReportContext = createContext({} as TestReportInstance);
export const useTestReport = () => {
  return useContext(TestReportContext);
};

/*
 * A container to display test results for Detox E2E test assertions.
 */
export const TestReportView: React.FC = ({ children }) => {
  const instanceRef = useRef<TestReportInstance>();

  const proxy: TestReportInstance = {
    update: (next) => instanceRef.current?.update(next),
  };

  return (
    <TestReportContext.Provider value={proxy}>
      <SafeAreaView style={styles.rootWrapper}>
        <View style={styles.reportWrapper}>
          <TestReportInspector
            ref={(instance) => {
              instanceRef.current = instance || undefined;
            }}
          />
        </View>
        <View style={styles.contentWrapper}>{children}</View>
      </SafeAreaView>
    </TestReportContext.Provider>
  );
};

export const TestReportInspector = forwardRef<TestReportInstance, {}>((_, ref) => {
  const [state, setState] = useState<TestReport>();
  useImperativeHandle(ref, () => ({ update: setState }));

  const testResultText = `Passed: ${state?.passed === undefined ? 'N/A' : String(state.passed)}`;
  const testResultErrorText = `Error: ${state?.error ? inspect(state?.error, 0) : 'N/A'}`;
  const testResultDataText = `Result: ${state?.result ? inspect(state?.result, 0) : 'N/A'}`;

  return (
    <View testID={`${state?.testID}-TestReport`} style={styles.resultContainer}>
      <Text style={styles.textLine}>{state?.testID ?? 'Nothing to inspect'}</Text>
      <Text
        testID={`${state?.testID}-TestResult`}
        accessibilityLabel={testResultText}
        style={styles.textLine}
        numberOfLines={1}
      >
        {testResultText}
      </Text>
      <Text
        testID={`${state?.testID}-TestResultError`}
        accessibilityLabel={testResultErrorText}
        style={styles.textLine}
        numberOfLines={1}
      >
        {testResultErrorText}
      </Text>
      <Text
        testID={`${state?.testID}-TestResultData`}
        accessibilityLabel={testResultDataText}
        style={styles.textLine}
        numberOfLines={1}
      >
        {testResultDataText}
      </Text>
    </View>
  );
});

const styles = StyleSheet.create({
  rootWrapper: {
    flex: 1,
    flexDirection: 'column',
  },
  contentWrapper: {
    flex: 1,
  },
  reportWrapper: {
    height: 100,
    paddingVertical: 16,
    paddingHorizontal: 16,
    backgroundColor: Colors.black,
    opacity: 0.85,
  },
  resultContainer: {
    flex: 1,
    flexDirection: 'column',
    justifyContent: 'center',
  },
  buttonContainer: {
    marginTop: 16,
    flexDirection: 'row',
    justifyContent: 'center',
    borderTopWidth: 1,
    borderTopColor: Colors.white,
  },
  textLine: {
    flex: 1,
    fontSize: 12,
    color: '#007AFF',
  },
});
