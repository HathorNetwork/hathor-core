//! ECDH key exchange and nonce derivation for shielded output recovery.

use secp256k1_zkp::{PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

use crate::error::HathorCtError;

/// Domain separator for nonce derivation, preventing cross-protocol reuse.
const NONCE_DOMAIN_SEPARATOR: &[u8] = b"Hathor_CT_nonce_v1";

/// Derive ECDH shared secret: `SHA256(privkey * pubkey)`.
pub fn derive_ecdh_shared_secret(
    privkey: &[u8; 32],
    pubkey: &[u8; 33],
) -> Result<[u8; 32], HathorCtError> {
    let sk = SecretKey::from_slice(privkey)
        .map_err(|e| HathorCtError::Secp256k1Error(e.to_string()))?;
    let pk = PublicKey::from_slice(pubkey)
        .map_err(|e| HathorCtError::Secp256k1Error(e.to_string()))?;

    let shared_point = pk
        .mul_tweak(SECP256K1, &sk.into())
        .map_err(|e| HathorCtError::Secp256k1Error(e.to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(shared_point.serialize());
    let result: [u8; 32] = hasher.finalize().into();
    Ok(result)
}

/// Derive the rewind nonce from a shared secret.
pub fn derive_rewind_nonce(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NONCE_DOMAIN_SEPARATOR);
    hasher.update(shared_secret);
    hasher.finalize().into()
}
