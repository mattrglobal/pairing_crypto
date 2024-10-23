const {getDefaultConfig, mergeConfig} = require('@react-native/metro-config');

/**
 * Metro configuration
 * https://facebook.github.io/metro/docs/configuration
 *
 * @type {import('metro-config').MetroConfig}
 */
const config = {
  // Reset the cache when starting the build. This could impact the performance, but useful
  // to make sure we are working against the correct resources.
  resetCache: true,
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
