/**
 * Loader for @hathor/ct-crypto-node NAPI addon.
 * Loads the prebuilt .node binary for the current platform.
 */
'use strict';

const path = require('path');
const os = require('os');

function loadNative() {
  const platform = os.platform();
  const arch = os.arch();
  const prebuildPath = path.join(
    __dirname, 'prebuilds', `${platform}-${arch}`, 'ct-crypto.node'
  );

  try {
    return require(prebuildPath);
  } catch (e) {
    throw new Error(
      `Failed to load @hathor/ct-crypto-node native addon for ${platform}-${arch}.\n` +
      `Tried: ${prebuildPath}\n` +
      `Error: ${e.message}\n\n` +
      `Make sure the prebuild for your platform is included in the package.\n` +
      `Supported platforms: darwin-arm64, darwin-x64, linux-x64, linux-arm64`
    );
  }
}

// Load and re-export all NAPI functions
const native = loadNative();
module.exports = native;
module.exports.loadNative = loadNative;
