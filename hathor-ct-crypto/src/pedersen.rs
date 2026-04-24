use secp256k1_zkp::{
    verify_commitments_sum_to_equal, Generator, PedersenCommitment, Tweak, SECP256K1,
};

use crate::error::{HathorCtError, Result};

/// Create a Pedersen commitment: `C = amount * H + blinding * G`.
///
/// `H` is the generator (asset tag), `G` is the standard secp256k1 generator.
pub fn create_commitment(
    amount: u64,
    blinding: &Tweak,
    generator: &Generator,
) -> Result<PedersenCommitment> {
    let commitment = PedersenCommitment::new(SECP256K1, amount, *blinding, *generator);
    Ok(commitment)
}

/// Create a trivial (zero-blinding) Pedersen commitment: `C = amount * H`.
///
/// Used for transparent inputs/outputs in the homomorphic balance equation.
pub fn create_trivial_commitment(amount: u64, generator: &Generator) -> Result<PedersenCommitment> {
    let commitment = PedersenCommitment::new_unblinded(SECP256K1, amount, *generator);
    Ok(commitment)
}

/// Verify that the sum of positive commitments equals the sum of negative commitments.
///
/// Returns true if: `sum(positive) = sum(negative)`.
pub fn verify_commitments_sum(
    positive: &[PedersenCommitment],
    negative: &[PedersenCommitment],
) -> bool {
    verify_commitments_sum_to_equal(SECP256K1, positive, negative)
}

/// Serialize a Pedersen commitment to 33 bytes (compressed point).
pub fn serialize_commitment(c: &PedersenCommitment) -> [u8; 33] {
    c.serialize()
}

/// Deserialize a Pedersen commitment from 33 bytes.
pub fn deserialize_commitment(bytes: &[u8]) -> Result<PedersenCommitment> {
    if bytes.len() != 33 {
        return Err(HathorCtError::InvalidCommitment(format!(
            "expected 33 bytes, got {}",
            bytes.len()
        )));
    }
    PedersenCommitment::from_slice(bytes)
        .map_err(|e| HathorCtError::InvalidCommitment(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::htr_asset_tag;

    #[test]
    fn test_create_commitment_deterministic() {
        let gen = htr_asset_tag();
        let blinding = Tweak::from_inner([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 42,
        ])
        .unwrap();

        let c1 = create_commitment(100, &blinding, &gen).unwrap();
        let c2 = create_commitment(100, &blinding, &gen).unwrap();
        assert_eq!(c1.serialize(), c2.serialize());
    }

    #[test]
    fn test_hiding_property() {
        let gen = htr_asset_tag();
        let b1 = Tweak::new(&mut rand::thread_rng());
        let b2 = Tweak::new(&mut rand::thread_rng());

        let c1 = create_commitment(100, &b1, &gen).unwrap();
        let c2 = create_commitment(100, &b2, &gen).unwrap();
        // Same amount, different blindings -> different commitments
        assert_ne!(c1.serialize(), c2.serialize());
    }

    #[test]
    fn test_binding_property() {
        let gen = htr_asset_tag();
        let b = Tweak::new(&mut rand::thread_rng());

        let c1 = create_commitment(100, &b, &gen).unwrap();
        let c2 = create_commitment(200, &b, &gen).unwrap();
        // Same blinding, different amounts -> different commitments
        assert_ne!(c1.serialize(), c2.serialize());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let gen = htr_asset_tag();
        let b = Tweak::new(&mut rand::thread_rng());
        let c = create_commitment(500, &b, &gen).unwrap();

        let bytes = serialize_commitment(&c);
        let c2 = deserialize_commitment(&bytes).unwrap();
        assert_eq!(c.serialize(), c2.serialize());
    }

    #[test]
    fn test_unblinded_homomorphic_property() {
        // With unblinded commitments, we can verify homomorphic sum
        let gen = htr_asset_tag();

        let c1 = create_trivial_commitment(300, &gen).unwrap();
        let c2 = create_trivial_commitment(700, &gen).unwrap();
        let c_total = create_trivial_commitment(1000, &gen).unwrap();

        assert!(verify_commitments_sum(&[c1, c2], &[c_total]));
    }

    #[test]
    fn test_blinded_homomorphic_property() {
        use secp256k1_zkp::{compute_adaptive_blinding_factor, CommitmentSecrets, ZERO_TWEAK};
        let gen = htr_asset_tag();

        let vbf1 = Tweak::new(&mut rand::thread_rng());
        let vbf2 = Tweak::new(&mut rand::thread_rng());

        let s1 = CommitmentSecrets::new(300, vbf1, ZERO_TWEAK);
        let s2 = CommitmentSecrets::new(700, vbf2, ZERO_TWEAK);

        let c1 = create_commitment(300, &vbf1, &gen).unwrap();
        let c2 = create_commitment(700, &vbf2, &gen).unwrap();

        // Compute balancing blinding for total
        let vbf_total =
            compute_adaptive_blinding_factor(SECP256K1, 1000, ZERO_TWEAK, &[s1, s2], &[]);

        let c_total = PedersenCommitment::new(SECP256K1, 1000, vbf_total, gen);
        assert!(verify_commitments_sum(&[c1, c2], &[c_total]));
    }

    #[test]
    fn test_deserialization_invalid_length() {
        let result = deserialize_commitment(&[0u8; 10]);
        assert!(result.is_err());
    }
}
