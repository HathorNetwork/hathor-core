"use strict";
/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the Apache-2.0 license found in the
 * LICENSE file in the root directory of this source tree.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadNative = void 0;
exports.loadNativeAddon = loadNativeAddon;
const native_1 = require("./native");
Object.defineProperty(exports, "loadNative", { enumerable: true, get: function () { return native_1.loadNative; } });
let cachedAddon = null;
/**
 * Load and return the native crypto addon, wrapped with bigint conversion.
 * The result is cached after the first call.
 */
function loadNativeAddon() {
    if (cachedAddon)
        return cachedAddon;
    const native = (0, native_1.loadNative)();
    cachedAddon = {
        decryptShieldedOutput(recipientPrivkey, ephemeralPubkey, commitment, rangeProof, tokenUid, assetCommitment) {
            const result = native.decryptShieldedOutput(recipientPrivkey, ephemeralPubkey, commitment, rangeProof, tokenUid, assetCommitment);
            return {
                value: BigInt(result.value),
                blindingFactor: result.blindingFactor,
                tokenUid: result.tokenUid,
                assetBlindingFactor: result.assetBlindingFactor,
                message: result.message,
                outputType: result.outputType,
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
            const result = native.createShieldedOutputWithBlinding(value, recipientPubkey, tokenUid, fullyShielded, blindingFactor);
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
//# sourceMappingURL=index.js.map