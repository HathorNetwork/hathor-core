/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the Apache-2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */

export { NativeAddon } from './native';
import { loadNative } from './native';
export { loadNative };

/**
 * Result of decrypting a shielded output.
 */
export interface DecryptedOutput {
  value: bigint;
  blindingFactor: Buffer;
  tokenUid: Buffer;
  assetBlindingFactor: Buffer | null;
  message: Buffer;
  outputType: 'AmountShielded' | 'FullShielded';
}

/**
 * Result of a rewind-only operation on a range proof.
 */
export interface RewindResult {
  value: bigint;
  blindingFactor: Buffer;
  message: Buffer;
}

/**
 * Result of creating a shielded output.
 */
export interface CreatedShieldedOutput {
  ephemeralPubkey: Buffer;
  commitment: Buffer;
  rangeProof: Buffer;
  blindingFactor: Buffer;
  assetCommitment: Buffer | null;
  assetBlindingFactor: Buffer | null;
}

/**
 * Input for computing balancing blinding factor.
 */
export interface BlindingInput {
  value: number;
  vbf: Buffer;
  gbf: Buffer;
}

/**
 * Public crypto addon interface with bigint values.
 */
export interface ICryptoAddon {
  decryptShieldedOutput(
    recipientPrivkey: Buffer,
    ephemeralPubkey: Buffer,
    commitment: Buffer,
    rangeProof: Buffer,
    tokenUid: Buffer,
    assetCommitment: Buffer | null,
  ): DecryptedOutput;

  rewindOnly(
    rangeProof: Buffer,
    commitment: Buffer,
    nonce: Buffer,
    generator: Buffer,
  ): RewindResult;

  deriveEcdhSharedSecret(privkey: Buffer, pubkey: Buffer): Buffer;
  deriveRewindNonce(sharedSecret: Buffer): Buffer;

  createShieldedOutput(
    value: number,
    recipientPubkey: Buffer,
    tokenUid: Buffer,
    fullyShielded: boolean,
  ): CreatedShieldedOutput;

  createShieldedOutputWithBlinding(
    value: number,
    recipientPubkey: Buffer,
    tokenUid: Buffer,
    fullyShielded: boolean,
    blindingFactor: Buffer,
  ): CreatedShieldedOutput;

  computeBalancingBlindingFactor(
    value: number,
    generatorBlindingFactor: Buffer,
    inputs: BlindingInput[],
    otherOutputs: BlindingInput[],
  ): Buffer;
}

let cachedAddon: ICryptoAddon | null = null;

/**
 * Load and return the native crypto addon, wrapped with bigint conversion.
 * The result is cached after the first call.
 */
export function loadNativeAddon(): ICryptoAddon {
  if (cachedAddon) return cachedAddon;
  const native = loadNative();

  cachedAddon = {
    decryptShieldedOutput(recipientPrivkey, ephemeralPubkey, commitment, rangeProof, tokenUid, assetCommitment) {
      const result = native.decryptShieldedOutput(
        recipientPrivkey, ephemeralPubkey, commitment, rangeProof, tokenUid, assetCommitment,
      );
      return {
        value: BigInt(result.value),
        blindingFactor: result.blindingFactor,
        tokenUid: result.tokenUid,
        assetBlindingFactor: result.assetBlindingFactor,
        message: result.message,
        outputType: result.outputType as 'AmountShielded' | 'FullShielded',
      };
    },

    rewindOnly(rangeProof, commitment, nonce, generator) {
      const result = native.rewindOnly(rangeProof, commitment, nonce, generator);
      return {
        value: BigInt(result.value),
        blindingFactor: result.blindingFactor,
        message: result.message,
      };
    },

    deriveEcdhSharedSecret(privkey, pubkey) {
      return native.deriveEcdhSharedSecret(privkey, pubkey);
    },

    deriveRewindNonce(sharedSecret) {
      return native.deriveRewindNonce(sharedSecret);
    },

    createShieldedOutput(value, recipientPubkey, tokenUid, fullyShielded) {
      const result = native.createShieldedOutput(value, recipientPubkey, tokenUid, fullyShielded);
      return {
        ephemeralPubkey: result.ephemeralPubkey,
        commitment: result.commitment,
        rangeProof: result.rangeProof,
        blindingFactor: result.blindingFactor,
        assetCommitment: result.assetCommitment,
        assetBlindingFactor: result.assetBlindingFactor,
      };
    },

    createShieldedOutputWithBlinding(value, recipientPubkey, tokenUid, fullyShielded, blindingFactor) {
      const result = native.createShieldedOutputWithBlinding(
        value, recipientPubkey, tokenUid, fullyShielded, blindingFactor,
      );
      return {
        ephemeralPubkey: result.ephemeralPubkey,
        commitment: result.commitment,
        rangeProof: result.rangeProof,
        blindingFactor: result.blindingFactor,
        assetCommitment: result.assetCommitment,
        assetBlindingFactor: result.assetBlindingFactor,
      };
    },

    computeBalancingBlindingFactor(value, generatorBlindingFactor, inputs, otherOutputs) {
      return native.computeBalancingBlindingFactor(value, generatorBlindingFactor, inputs, otherOutputs);
    },
  };

  return cachedAddon;
}
