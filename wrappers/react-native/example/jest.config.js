/*
 * Copyright 2022 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
const package = require('./package.json');

module.exports = {
  displayName: package.name,
  preset: 'react-native',
  maxWorkers: 1,
  testTimeout: 120000,
  verbose: true,
  reporters: ['detox/runners/jest/reporter'],
  globalSetup: 'detox/runners/jest/globalSetup',
  globalTeardown: 'detox/runners/jest/globalTeardown',
  testEnvironment: './__tests__/detox-environment',
  testMatch: ['**/*.e2e.ts'],
  testPathIgnorePatterns: ['/node_modules/', '/lib/'],
  collectCoverage: true,
  coverageDirectory: './jest_results/coverage/',
  coverageReporters: [['lcov', { projectRoot: '../' }], 'text'],
  coveragePathIgnorePatterns: ['<rootDir>/__tests__'],
  // https://github.com/facebook/jest/issues/7136#issuecomment-565976599
  restoreMocks: true,
  clearMocks: true,
  resetMocks: true,
};
