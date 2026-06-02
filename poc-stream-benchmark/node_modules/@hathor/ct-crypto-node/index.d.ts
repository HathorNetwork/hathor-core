/// Type declarations for @hathor/ct-crypto-node NAPI addon

// Generator / tag derivation
export function deriveAssetTag(tokenUid: Buffer): Buffer;
export function htrAssetTag(): Buffer;
export function deriveTag(tokenUid: Buffer): Buffer;
export function createAssetCommitment(tagBytes: Buffer, rAsset: Buffer): Buffer;

// Pedersen commitments
export function createCommitment(amount: bigint, blinding: Buffer, generator: Buffer): Buffer;
export function createTrivialCommitment(amount: bigint, generator: Buffer): Buffer;
export function verifyCommitmentsSum(positive: Buffer[], negative: Buffer[]): boolean;

// Range proofs
export function createRangeProof(
  amount: bigint, blinding: Buffer, commitment: Buffer, generator: Buffer,
  message?: Buffer | null, nonce?: Buffer | null,
): Buffer;
export function verifyRangeProof(proof: Buffer, commitment: Buffer, generator: Buffer): boolean;

export interface RewindResult {
  value: bigint;
  blindingFactor: Buffer;
  message: Buffer;
}
export function rewindRangeProof(
  proof: Buffer, commitment: Buffer, nonce: Buffer, generator: Buffer,
): RewindResult;

// Validation
export function validateCommitment(data: Buffer): boolean;
export function validateGenerator(data: Buffer): boolean;

// Surjection proofs
export interface SurjectionDomainEntry {
  generator: Buffer;
  tag: Buffer;
  blindingFactor: Buffer;
}
export function createSurjectionProof(
  codomainTag: Buffer, codomainBlindingFactor: Buffer, domain: SurjectionDomainEntry[],
): Buffer;
export function verifySurjectionProof(proof: Buffer, codomain: Buffer, domain: Buffer[]): boolean;

// Balance verification
export interface TransparentEntry {
  amount: bigint;
  tokenUid: Buffer;
}
export function verifyBalance(
  transparentInputs: TransparentEntry[], shieldedInputs: Buffer[],
  transparentOutputs: TransparentEntry[], shieldedOutputs: Buffer[],
): boolean;

// Blinding factor management
export interface BlindingEntry {
  value: bigint;
  valueBlindingFactor: Buffer;
  generatorBlindingFactor: Buffer;
}
export function computeBalancingBlindingFactor(
  value: bigint, generatorBlindingFactor: Buffer,
  inputs: BlindingEntry[], otherOutputs: BlindingEntry[],
): Buffer;

// Random generation
export function generateRandomBlindingFactor(): Buffer;

export interface EphemeralKeypair {
  privateKey: Buffer;
  publicKey: Buffer;
}
export function generateEphemeralKeypair(): EphemeralKeypair;

// ECDH
export function deriveEcdhSharedSecret(privateKey: Buffer, peerPubkey: Buffer): Buffer;
export function deriveRewindNonce(sharedSecret: Buffer): Buffer;

// Shielded output creation
export interface CreatedAmountShieldedOutput {
  ephemeralPubkey: Buffer;
  commitment: Buffer;
  rangeProof: Buffer;
  blindingFactor: Buffer;
}
export function createAmountShieldedOutput(
  value: bigint, recipientPubkey: Buffer, tokenUid: Buffer, valueBlindingFactor: Buffer,
): CreatedAmountShieldedOutput;

export interface CreatedShieldedOutput {
  ephemeralPubkey: Buffer;
  commitment: Buffer;
  rangeProof: Buffer;
  blindingFactor: Buffer;
  assetCommitment: Buffer | null;
  assetBlindingFactor: Buffer | null;
}
export function createShieldedOutputWithBothBlindings(
  value: bigint, recipientPubkey: Buffer, tokenUid: Buffer,
  valueBlindingFactor: Buffer, assetBlindingFactor: Buffer,
): CreatedShieldedOutput;

// Shielded output rewind
export interface RewoundAmountShieldedOutput {
  value: bigint;
  blindingFactor: Buffer;
}
export function rewindAmountShieldedOutput(
  privateKey: Buffer, ephemeralPubkey: Buffer, commitment: Buffer,
  rangeProof: Buffer, tokenUid: Buffer,
): RewoundAmountShieldedOutput;

export interface RewoundFullShieldedOutput {
  value: bigint;
  blindingFactor: Buffer;
  tokenUid: Buffer;
  assetBlindingFactor: Buffer;
}
export function rewindFullShieldedOutput(
  privateKey: Buffer, ephemeralPubkey: Buffer, commitment: Buffer,
  rangeProof: Buffer, assetCommitment: Buffer,
): RewoundFullShieldedOutput;

// Constants
export function getCommitmentSize(): number;
export function getGeneratorSize(): number;
export function getZeroTweak(): Buffer;

export function loadNative(): typeof import('@hathor/ct-crypto-node');
