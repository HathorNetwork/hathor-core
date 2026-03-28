"use strict";
/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the Apache-2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadNative = loadNative;
const path = require("path");
/**
 * Resolves the platform-specific prebuild directory name.
 */
function getPlatformDir() {
    const platform = process.platform;
    const arch = process.arch;
    return `${platform}-${arch}`;
}
/**
 * Loads the native .node addon.
 *
 * Search order:
 * 1. Prebuilds directory (for published packages)
 * 2. Cargo target/release directory (for local development)
 */
function loadNative() {
    const platformDir = getPlatformDir();
    // Try prebuilds first
    const prebuildPath = path.join(__dirname, '..', 'prebuilds', platformDir, 'ct-crypto.node');
    try {
        return require(prebuildPath);
    }
    catch {
        // Fall through to development path
    }
    // Try cargo target/release (development)
    const devPaths = [
        path.join(__dirname, '..', '..', 'target', 'release', 'libhathor_ct_crypto.node'),
        path.join(__dirname, '..', '..', 'target', 'release', 'hathor_ct_crypto.node'),
    ];
    for (const devPath of devPaths) {
        try {
            return require(devPath);
        }
        catch {
            // Try next path
        }
    }
    throw new Error(`Failed to load native addon for platform ${platformDir}. ` +
        `Ensure either prebuilds are available or the crate is built with: ` +
        `cargo build --release --features napi`);
}
//# sourceMappingURL=native.js.map