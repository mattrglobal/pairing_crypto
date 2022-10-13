const package = require("./package.json");

module.exports = {
  displayName: package.name,
  preset: "react-native",
  reporters: ["detox/runners/jest/streamlineReporter"],
  testEnvironment: "./__tests__/detox-environment",
  testRunner: "jest-circus/runner",
  testTimeout: 20000,
  testMatch: ["**/*.e2e.ts"],
  testPathIgnorePatterns: ["/node_modules/", "/lib/"],
  verbose: true,
  collectCoverage: true,
  coverageDirectory: "./jest_results/coverage/",
  coverageReporters: [["lcov", { projectRoot: "../" }], "text"],
  coveragePathIgnorePatterns: ["<rootDir>/__tests__"],
  // https://github.com/facebook/jest/issues/7136#issuecomment-565976599
  restoreMocks: true,
  clearMocks: true,
  resetMocks: true
};
