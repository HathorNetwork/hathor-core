use std::ops::Range;

use secp256k1_zkp::{Generator, PedersenCommitment, RangeProof, SecretKey, Tweak, SECP256K1};

use crate::error::{HathorCtError, Result};

/// Create a Bulletproof range proof proving that the committed amount is in [0, 2^64).
///
/// # Arguments
/// * `amount` - The secret value to prove is in range
/// * `blinding` - The blinding factor (Tweak) used in the commitment
/// * `commitment` - The Pedersen commitment to prove
/// * `generator` - The generator (asset tag) used in the commitment
/// * `message` - Optional message to embed in the proof
/// * `nonce` - Optional nonce key. If None, a random nonce is used. If Some, the provided
///   key is used as the nonce, enabling `rewind_range_proof` to recover the committed values.
pub fn create_range_proof(
    amount: u64,
    blinding: &Tweak,
    commitment: &PedersenCommitment,
    generator: &Generator,
    message: Option<&[u8]>,
    nonce: Option<&SecretKey>,
) -> Result<RangeProof> {
    let msg = message.unwrap_or(&[]);
    // Use provided nonce or generate a random one
    let sk = match nonce {
        Some(key) => *key,
        None => SecretKey::new(&mut rand::thread_rng()),
    };

    let proof = RangeProof::new(
        SECP256K1,
        1, // min_value: reject zero-amount commitments (VULN-005)
        *commitment,
        amount,     // value
        *blinding,  // commitment_blinding
        msg,        // message
        &[],        // additional_commitment
        sk,         // sk (nonce key)
        0,          // exp
        0,          // min_bits (0 = auto)
        *generator, // additional_generator
    )
    .map_err(|e| HathorCtError::RangeProofError(e.to_string()))?;

    Ok(proof)
}

/// Rewind a Bulletproof range proof to recover the committed value, blinding factor, and message.
///
/// This requires the same nonce key that was used when creating the proof.
/// Returns (value, blinding_factor, message) on success.
pub fn rewind_range_proof(
    proof: &RangeProof,
    commitment: &PedersenCommitment,
    nonce: &SecretKey,
    generator: &Generator,
) -> Result<(u64, Tweak, Vec<u8>)> {
    let (opening, _range) = proof
        .rewind(SECP256K1, *commitment, *nonce, &[], *generator)
        .map_err(|e| HathorCtError::RangeProofError(format!("range proof rewind failed: {}", e)))?;

    Ok((opening.value, opening.blinding_factor, opening.message.into_vec()))
}

/// Verify a Bulletproof range proof.
///
/// Checks that the committed value is in the valid range.
/// Returns the proven range [min, max) on success.
pub fn verify_range_proof(
    proof: &RangeProof,
    commitment: &PedersenCommitment,
    generator: &Generator,
) -> Result<Range<u64>> {
    let range = proof
        .verify(SECP256K1, *commitment, &[], *generator)
        .map_err(|e| {
            HathorCtError::RangeProofError(format!("range proof verification failed: {}", e))
        })?;
    Ok(range)
}

/// Batch-verify multiple range proofs.
pub fn batch_verify_range_proofs(
    proofs: &[RangeProof],
    commitments: &[PedersenCommitment],
    generators: &[Generator],
) -> Result<()> {
    if proofs.len() != commitments.len() || proofs.len() != generators.len() {
        return Err(HathorCtError::RangeProofError(
            "mismatched lengths for batch verification".into(),
        ));
    }

    for (i, ((proof, commitment), generator)) in proofs
        .iter()
        .zip(commitments.iter())
        .zip(generators.iter())
        .enumerate()
    {
        let range = verify_range_proof(proof, commitment, generator)
            .map_err(|e| HathorCtError::RangeProofError(format!("proof {} failed: {}", i, e)))?;
        if range.start < 1 {
            return Err(HathorCtError::RangeProofError(format!(
                "proof {} has min_value {} < 1 (zero-amount rejected)",
                i, range.start
            )));
        }
    }

    Ok(())
}

/// Serialize a range proof to bytes.
pub fn serialize_range_proof(proof: &RangeProof) -> Vec<u8> {
    proof.serialize()
}

/// Deserialize a range proof from bytes.
pub fn deserialize_range_proof(bytes: &[u8]) -> Result<RangeProof> {
    RangeProof::from_slice(bytes).map_err(|e| {
        HathorCtError::RangeProofError(format!("failed to deserialize range proof: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::htr_asset_tag;
    use crate::pedersen::create_commitment;

    #[test]
    fn test_valid_range_proof() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 1000u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        let proof = create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
        assert!(verify_range_proof(&proof, &commitment, &gen).is_ok());
    }

    #[test]
    fn test_zero_amount_rejected() {
        // VULN-005: Zero-amount range proofs must be rejected (min_value=1).
        // With min_value=1, creating a range proof for amount=0 should fail.
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 0u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        // Creating a range proof with amount=0 and min_value=1 should fail
        let result = create_range_proof(amount, &blinding, &commitment, &gen, None, None);
        assert!(result.is_err(), "zero-amount range proof creation should fail with min_value=1");
    }

    #[test]
    fn test_large_amount() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 1_000_000_000u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        let proof = create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
        assert!(verify_range_proof(&proof, &commitment, &gen).is_ok());
    }

    #[test]
    fn test_wrong_commitment_fails() {
        let gen = htr_asset_tag();
        let blinding1 = Tweak::new(&mut rand::thread_rng());
        let blinding2 = Tweak::new(&mut rand::thread_rng());

        let commitment1 = create_commitment(1000, &blinding1, &gen).unwrap();
        let commitment2 = create_commitment(2000, &blinding2, &gen).unwrap();

        let proof = create_range_proof(1000, &blinding1, &commitment1, &gen, None, None).unwrap();
        // Verify with wrong commitment should fail
        assert!(verify_range_proof(&proof, &commitment2, &gen).is_err());
    }

    #[test]
    fn test_batch_verify() {
        let gen = htr_asset_tag();
        let amounts = [100u64, 200, 300];
        let mut proofs = Vec::new();
        let mut commitments = Vec::new();
        let generators = vec![gen; 3];

        for amount in amounts {
            let blinding = Tweak::new(&mut rand::thread_rng());
            let commitment = create_commitment(amount, &blinding, &gen).unwrap();
            let proof = create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
            proofs.push(proof);
            commitments.push(commitment);
        }

        assert!(batch_verify_range_proofs(&proofs, &commitments, &generators).is_ok());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let commitment = create_commitment(500, &blinding, &gen).unwrap();
        let proof = create_range_proof(500, &blinding, &commitment, &gen, None, None).unwrap();

        let bytes = serialize_range_proof(&proof);
        let proof2 = deserialize_range_proof(&bytes).unwrap();
        assert!(verify_range_proof(&proof2, &commitment, &gen).is_ok());
    }

    #[test]
    fn test_proof_with_message() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 42u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        let msg = b"test message";
        let proof = create_range_proof(amount, &blinding, &commitment, &gen, Some(msg), None).unwrap();
        assert!(verify_range_proof(&proof, &commitment, &gen).is_ok());
    }

    #[test]
    fn test_create_with_optional_nonce() {
        // Backward compat: None nonce generates random (proof still verifies)
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 777u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();
        let proof = create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
        assert!(verify_range_proof(&proof, &commitment, &gen).is_ok());
    }

    #[test]
    fn test_rewind_roundtrip() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 12345u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        let nonce = SecretKey::new(&mut rand::thread_rng());
        let msg = b"hello world rewind";
        let proof = create_range_proof(amount, &blinding, &commitment, &gen, Some(msg), Some(&nonce)).unwrap();

        // Verify the proof is valid
        assert!(verify_range_proof(&proof, &commitment, &gen).is_ok());

        // Rewind to recover value, blinding, and message
        let (recovered_value, recovered_blinding, recovered_message) =
            rewind_range_proof(&proof, &commitment, &nonce, &gen).unwrap();

        assert_eq!(recovered_value, amount);
        assert_eq!(recovered_blinding.as_ref(), blinding.as_ref());
        // The message is padded to 4096 bytes; check that it starts with our message
        assert!(recovered_message.starts_with(msg));
    }

    #[test]
    fn test_rewind_wrong_nonce_fails() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 999u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        let nonce = SecretKey::new(&mut rand::thread_rng());
        let wrong_nonce = SecretKey::new(&mut rand::thread_rng());

        let proof = create_range_proof(amount, &blinding, &commitment, &gen, None, Some(&nonce)).unwrap();

        // Rewind with wrong nonce should fail
        let result = rewind_range_proof(&proof, &commitment, &wrong_nonce, &gen);
        assert!(result.is_err());
    }
}
