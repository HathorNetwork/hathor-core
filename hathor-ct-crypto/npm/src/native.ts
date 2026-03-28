/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the Apache-2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from 'path';

/**
 * Raw native addon interface as exported by the napi-rs compiled .node file.
 */
export interface NativeAddon {
  decryptShieldedOutput(
    recipientPrivkey: Buffer,
    ephemeralPubkey: Buffer,
    commitment: Buffer,
    rangeProof: Buffer,
    tokenUid: Buffer,
    assetCommitment: Buffer | null,
  ): {
    value: number;
    blindingFactor: Buffer;
    tokenUid: Buffer;
    assetBlindingFactor: Buffer | null;
    message: Buffer;
    outputType: string;
  };

  rewindOnly(
    rangeProof: Buffer,
    commitment: Buffer,
    nonce: Buffer,
    generator: Buffer,
  ): {
    value: number;
    blindingFactor: Buffer;
    message: Buffer;
  };

  deriveEcdhSharedSecret(privkey: Buffer, pubkey: Buffer): Buffer;
  deriveRewindNonce(sharedSecret: Buffer): Buffer;

  createShieldedOutput(
    value: number,
    recipientPubkey: Buffer,
    tokenUid: Buffer,
    fullyShielded: boolean,
  ): {
    ephemeralPubkey: Buffer;
    commitment: Buffer;
    rangeProof: Buffer;
    blindingFactor: Buffer;
    assetCommitment: Buffer | null;
    assetBlindingFactor: Buffer | null;
  };

  createShieldedOutputWithBlinding(
    value: number,
    recipientPubkey: Buffer,
    tokenUid: Buffer,
    fullyShielded: boolean,
    blindingFactor: Buffer,
  ): {
    ephemeralPubkey: Buffer;
    commitment: Buffer;
    rangeProof: Buffer;
    blindingFactor: Buffer;
    assetCommitment: Buffer | null;
    assetBlindingFactor: Buffer | null;
  };

  computeBalancingBlindingFactor(
    value: number,
    generatorBlindingFactor: Buffer,
    inputs: Array<{ value: number; vbf: Buffer; gbf: Buffer }>,
    otherOutputs: Array<{ value: number; vbf: Buffer; gbf: Buffer }>,
  ): Buffer;
}

/**
 * Resolves the platform-specific prebuild directory name.
 */
function getPlatformDir(): string {
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
export function loadNative(): NativeAddon {
  const platformDir = getPlatformDir();

  // Try prebuilds first
  const prebuildPath = path.join(__dirname, '..', 'prebuilds', platformDir, 'ct-crypto.node');
  try {
    return require(prebuildPath);
  } catch {
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
    } catch {
      // Try next path
    }
  }

  throw new Error(
    `Failed to load native addon for platform ${platformDir}. ` +
      `Ensure either prebuilds are available or the crate is built with: ` +
      `cargo build --release --features napi`,
  );
}
