const { FixturesEnvName, readFixtureFiles } = require('./__fixtures__/fixture-loader');

/**
 * Babel plugin that injects the `bbs-fixtures-generator` produced test fixtures
 * into the Example App.
 *
 * The loaded fixtures can be access from `process.env.__FIXTURES__`.
 */
module.exports = (api, options) => {
  const t = api.types;
  const { fixturesDir } = options;

  return {
    name: 'fixtures-loader',
    visitor: {
      MemberExpression(path, { opts }) {
        if (path.get('object').matchesPattern('process.env')) {
          const key = path.toComputedKey();
          if (t.isStringLiteral(key)) {
            const importedId = key.value;
            if (importedId === FixturesEnvName) {
              const fixtures = readFixtureFiles(fixturesDir);
              path.replaceWith(t.valueToNode(fixtures));
            }
          }
        }
      },
    },
  };
};
