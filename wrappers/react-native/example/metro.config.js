const path = require('path');
const escape = require('escape-string-regexp');
const exclusionList = require('metro-config/src/defaults/exclusionList');
const pak = require('../package.json');

const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

const root = path.resolve(__dirname, '..');

const modules = Object.keys({
  ...pak.peerDependencies,
});

const {
  resolver: { sourceExts, assetExts },
} = getDefaultConfig(__dirname);

const config = {
  projectRoot: __dirname,
  watchFolders: [root],

  // Reset the cache when starting the build. This could impact the performance, but useful
  // to make sure we are working against the correct resources.
  resetCache: true,

  // We need to make sure that only one version is loaded for peerDependencies
  // So we block them at the root, and alias them to the versions in example's node_modules
  resolver: {
    blacklistRE: exclusionList(
      modules.map((m) => {
        return new RegExp(`^${escape(path.join(root, 'node_modules', m))}\\/.*$`);
      })
    ),

    extraNodeModules: modules.reduce((acc, name) => {
      acc[name] = path.join(__dirname, 'node_modules', name);
      return acc;
    }, {}),

    assetExts: assetExts.filter(ext => ext !== 'svg'),
    sourceExts: [...sourceExts, 'svg'],
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
