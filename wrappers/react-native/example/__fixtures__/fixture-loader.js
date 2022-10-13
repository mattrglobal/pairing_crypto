const fs = require('fs');
const path = require('path');

const FixturesDir = path.join(__dirname, '../../../../tests/fixtures/bbs');
const FixturesEnvName = '__FIXTURES__';

const readFixtureFiles = (dir = FixturesDir, results = {}) => {
  try {
    return fs.readdirSync(dir).reduce((accu, fileName) => {
      const filePath = dir + '/' + fileName;
      if (fs.statSync(filePath).isDirectory()) {
        return { ...accu, [fileName]: readFixtureFiles(filePath) };
      }
      if (filePath.endsWith('json')) {
        const source = filePath;
        const name = fileName.replace('.json', '');
        const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        return { ...accu, [name]: { name, source, value } };
      }
    }, results);
  } catch (error) {
    console.error('[fixture-loader] Failed to load fixtures', error);
    return results;
  }
};

module.exports = {
  FixturesDir,
  FixturesEnvName,
  readFixtureFiles,
};
