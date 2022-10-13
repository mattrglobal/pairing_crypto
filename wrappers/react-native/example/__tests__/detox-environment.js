const { DetoxCircusEnvironment, SpecReporter, WorkerAssignReporter } = require('detox/runners/jest-circus');
const { FixturesEnvName, readFixtureFiles } = require('../__fixtures__/fixture-loader');

class CustomDetoxEnvironment extends DetoxCircusEnvironment {
  constructor(config, context) {
    super(config, context);

    // Can be safely removed, if you are content with the default value (=300000ms)
    // this.initTimeout = 300000;
    this.initTimeout = 900000;

    // This takes care of generating status logs on a per-spec basis. By default, Jest only reports at file-level.
    // This is strictly optional.
    this.registerListeners({
      SpecReporter,
      WorkerAssignReporter,
    });
  }

  async setup() {
    await super.setup();

    // Load and inject the generated test fixtures to be accessed from the tests suites.
    process.env[FixturesEnvName] = readFixtureFiles();
  }
}

module.exports = CustomDetoxEnvironment;
