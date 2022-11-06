import { useRef } from 'react';

export type TestCaseInstance = {
  readonly runTest: () => Promise<void>;
};

export type TestGroupProps = {
  readonly register: (key: string) => (instance: TestCaseInstance | null) => void;
  readonly runAll: () => Promise<void>;
};
export const useTestGroup = (): TestGroupProps => {
  const instancesRef = useRef(new Map<string, TestCaseInstance>());

  const register = (key: string) => (instance: TestCaseInstance | null) => {
    if (!instance) {
      instancesRef.current.delete(key);
    } else {
      instancesRef.current.set(key, instance);
    }
  };

  const runAll = async (): Promise<void> => {
    for (const instance of Array.from(instancesRef.current.values())) {
      await instance.runTest();
    }
  };

  return { register, runAll };
};
