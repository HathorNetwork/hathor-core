use secp256k1_zkp::{Generator, Tag, Tweak, SECP256K1};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use crate::error::{HathorCtError, Result};
use crate::types::TokenUid;

/// Domain separator for NUMS asset tag derivation.
const ASSET_TAG_DOMAIN: &[u8] = b"Hathor_AssetTag_v1";

/// Derive a deterministic NUMS Tag for a given token UID.
///
/// Uses SHA-256: `tag = SHA256(domain || token_uid)` to produce a 32-byte Tag.
pub fn derive_tag(token_uid: &TokenUid) -> Result<Tag> {
    let mut hasher = Sha256::new();
    hasher.update(ASSET_TAG_DOMAIN);
    hasher.update(token_uid);
    let hash = hasher.finalize();
    let tag = Tag::from(Into::<[u8; 32]>::into(hash));
    Ok(tag)
}

/// Derive an unblinded asset generator for a given token UID.
///
/// Returns `Generator::new_unblinded(SECP256K1, tag)` where tag is derived from the token UID.
pub fn derive_asset_tag(token_uid: &TokenUid) -> Result<Generator> {
    let tag = derive_tag(token_uid)?;
    let generator = Generator::new_unblinded(SECP256K1, tag);
    Ok(generator)
}

/// Return the cached HTR asset tag (token_uid = [0; 32]).
pub fn htr_asset_tag() -> Generator {
    static HTR_TAG: OnceLock<Generator> = OnceLock::new();
    *HTR_TAG.get_or_init(|| {
        derive_asset_tag(&[0u8; 32]).expect("HTR asset tag derivation should never fail")
    })
}

/// Return the cached HTR Tag (not blinded into Generator).
pub fn htr_tag() -> Tag {
    static HTR_RAW_TAG: OnceLock<Tag> = OnceLock::new();
    *HTR_RAW_TAG
        .get_or_init(|| derive_tag(&[0u8; 32]).expect("HTR tag derivation should never fail"))
}

/// Create a blinded asset commitment: Generator from `tag` blinded by `r_asset`.
///
/// This hides the token type by adding randomness to the base asset tag.
pub fn create_asset_commitment(tag: &Tag, r_asset: &Tweak) -> Result<Generator> {
    let blinded = Generator::new_blinded(SECP256K1, *tag, *r_asset);
    Ok(blinded)
}

/// Create a trivial (unblinded) asset commitment for a token.
///
/// This is equivalent to `derive_asset_tag(token_uid)`.
pub fn trivial_asset_commitment(token_uid: &TokenUid) -> Result<Generator> {
    derive_asset_tag(token_uid)
}

/// Serialize a generator to 33 bytes.
pub fn serialize_generator(gen: &Generator) -> [u8; 33] {
    gen.serialize()
}

/// Deserialize a generator from 33 bytes.
pub fn deserialize_generator(bytes: &[u8]) -> Result<Generator> {
    Generator::from_slice(bytes).map_err(|e| HathorCtError::InvalidGenerator(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_htr_asset_tag_deterministic() {
        let tag1 = htr_asset_tag();
        let tag2 = htr_asset_tag();
        assert_eq!(tag1.serialize(), tag2.serialize());
    }

    #[test]
    fn test_different_tokens_different_tags() {
        let tag1 = derive_asset_tag(&[0u8; 32]).unwrap();
        let tag2 = derive_asset_tag(&[1u8; 32]).unwrap();
        assert_ne!(tag1.serialize(), tag2.serialize());
    }

    #[test]
    fn test_derive_asset_tag_deterministic() {
        let uid = [42u8; 32];
        let tag1 = derive_asset_tag(&uid).unwrap();
        let tag2 = derive_asset_tag(&uid).unwrap();
        assert_eq!(tag1.serialize(), tag2.serialize());
    }

    #[test]
    fn test_create_asset_commitment_differs_from_unblinded() {
        let uid = [1u8; 32];
        let tag = derive_tag(&uid).unwrap();
        let unblinded = derive_asset_tag(&uid).unwrap();
        let r_asset = Tweak::new(&mut rand::thread_rng());
        let blinded = create_asset_commitment(&tag, &r_asset).unwrap();
        // Blinded commitment should differ from the unblinded tag
        assert_ne!(blinded.serialize(), unblinded.serialize());
    }

    #[test]
    fn test_generator_serialization_roundtrip() {
        let tag = htr_asset_tag();
        let bytes = serialize_generator(&tag);
        let tag2 = deserialize_generator(&bytes).unwrap();
        assert_eq!(tag.serialize(), tag2.serialize());
    }

    #[test]
    fn test_trivial_asset_commitment_equals_derive() {
        let uid = [5u8; 32];
        let tag = derive_asset_tag(&uid).unwrap();
        let trivial = trivial_asset_commitment(&uid).unwrap();
        assert_eq!(tag.serialize(), trivial.serialize());
    }

    #[test]
    fn test_zero_tweak_gives_unblinded() {
        use secp256k1_zkp::ZERO_TWEAK;
        let uid = [3u8; 32];
        let tag = derive_tag(&uid).unwrap();
        let unblinded = Generator::new_unblinded(SECP256K1, tag);
        let zero_blinded = Generator::new_blinded(SECP256K1, tag, ZERO_TWEAK);
        assert_eq!(unblinded.serialize(), zero_blinded.serialize());
    }
}
