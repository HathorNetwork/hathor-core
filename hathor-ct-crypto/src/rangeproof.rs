use std::env;
use std::ops::Range;
use std::sync::OnceLock;

use rayon::prelude::*;

use secp256k1_zkp::{Generator, PedersenCommitment, RangeProof, SecretKey, Tweak, SECP256K1};

use crate::error::{HathorCtError, Result};

/// Default number of bits proven by every range proof.
///
/// Using a fixed width ensures all proofs are the same size regardless of the
/// committed value, preventing proof-size side-channels.
///
/// BENCHMARK BRANCH: the default is **64** (was 40 upstream). 40 bits covers
/// values up to 2^40 − 1 (≈1 trillion); 64 bits is the FULL range of a u64 amount
/// and the largest the proof system supports. (We initially tried 82 per request,
/// but the committed `amount` is a u64 and secp256k1-zkp's Borromean range proof
/// caps min_bits at 64 — 82/96 fail at creation with "failed to generate range
/// proof". 40→3213 B, 64→5070 B; >64 is impossible without a wider amount type.)
///
/// TODO (parked, see planning/05-desktop-app-packaging-design.md): ranges wider than 64 bits are
/// reachable by LIMB DECOMPOSITION — commit to v = v_lo + 2^64*v_hi as C_lo and C_hi, range-prove
/// each limb over [0, 2^64), and have the verifier additionally check C == C_lo + 2^64*C_hi. The
/// point equation is not optional: without it the limbs are unrelated to the committed value.
/// Costs ~2x proof bytes and ~2x verification, plus a wire-format and balance-equation change.
/// Not built because every Hathor amount is u64, so no value can need it. A cheaper native option
/// for magnitude (at the cost of low-digit precision) is the C API's base-10 `exp` parameter.
///
/// TOGGLEABLE at runtime via the `HATHOR_RANGE_PROOF_BITS` env var (read at proof
/// creation time, so it can be changed per build without recompiling). Valid range
/// is 1..=64. Verify does not need the bit-width — a Borromean proof is
/// self-describing — so only creation reads this; mixing widths across txs is fine.
pub const RANGE_PROOF_BITS: usize = 64;

/// Resolve the range-proof bit-width: the `HATHOR_RANGE_PROOF_BITS` env override if
/// set and parseable, otherwise the `RANGE_PROOF_BITS` default. Read on every
/// creation (cheap; creation happens in untimed benchmark setup), so a benchmark can
/// sweep widths within a single process by changing the env between batches.
fn configured_range_proof_bits() -> u8 {
    match env::var("HATHOR_RANGE_PROOF_BITS") {
        Ok(v) => v.trim().parse::<u8>().unwrap_or(RANGE_PROOF_BITS as u8),
        Err(_) => RANGE_PROOF_BITS as u8,
    }
}

/// Create a Borromean range proof proving that the committed amount is in [1, 2^RANGE_PROOF_BITS).
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
        1, // min_value: reject zero-amount commitments
        *commitment,
        amount,                 // value
        *blinding,              // commitment_blinding
        msg,                    // message
        &[],                    // additional_commitment
        sk,                     // sk (nonce key)
        0,                      // exp
        configured_range_proof_bits(), // min_bits: default RANGE_PROOF_BITS (64), env-toggleable
        *generator,             // additional_generator
    )
    .map_err(|e| HathorCtError::RangeProofError(e.to_string()))?;

    Ok(proof)
}

/// Rewind a Borromean range proof to recover the committed value, blinding factor, and message.
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

    Ok((
        opening.value,
        opening.blinding_factor,
        opening.message.into_vec(),
    ))
}

/// Verify a Borromean range proof.
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
    // Enforce min_value >= 1 to reject zero-amount commitments.
    // This check is also in the FFI wrappers, but we enforce it here as defense-in-depth.
    if range.start < 1 {
        return Err(HathorCtError::RangeProofError(
            "range proof min_value must be >= 1 (zero-amount commitments are not allowed)".into(),
        ));
    }
    Ok(range)
}

/// The rayon pool used for range-proof verification.
///
/// Sized on FIRST USE from `HATHOR_SHIELDED_WORKERS`, falling back to rayon's default (one thread
/// per logical core). Like htr-lib's script pool this is a `OnceLock`, so a later call with a
/// different worker count reuses the existing pool — a worker sweep must therefore use one
/// PROCESS per point.
///
/// Sizing matters: on the reference machine (4 physical / 8 logical cores) running one worker per
/// *logical* core measured ~2x WORSE than one per physical core, because the extra threads preempt
/// the single-threaded driver and RocksDB's compaction. The benchmark harness exports the env var
/// so this pool and the script pool agree on a budget instead of each claiming every core.
fn verify_pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let workers = std::env::var("HATHOR_SHIELDED_WORKERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0); // 0 => rayon decides
        let mut builder = rayon::ThreadPoolBuilder::new().thread_name(|i| format!("rp-verify-{i}"));
        if workers > 0 {
            builder = builder.num_threads(workers);
        }
        builder
            .build()
            .expect("a rayon pool with a valid thread count always builds")
    })
}

/// Verify many range proofs in parallel, one result per input, in input order.
///
/// `None` means the proof is valid; `Some(message)` carries the reason it is not. Results are
/// returned per index rather than short-circuiting on the first failure, because the caller must
/// be able to say WHICH shielded output was bad — the sequential Python loop this replaces raised
/// `InvalidRangeProofError('shielded output {i}: ...')`, and losing that index would degrade
/// diagnostics on a consensus path. The two failure messages match the ones the per-proof binding
/// produced, so the Python-visible behaviour is unchanged.
///
/// Verification is a pure function of (proof, commitment, generator) with no shared state, so this
/// is embarrassingly parallel; the only ordering guarantee needed is that results line up with
/// inputs, which `par_iter().map().collect()` provides.
pub fn verify_range_proofs_parallel(
    proofs: &[RangeProof],
    commitments: &[PedersenCommitment],
    generators: &[Generator],
) -> Result<Vec<Option<String>>> {
    if proofs.len() != commitments.len() || proofs.len() != generators.len() {
        return Err(HathorCtError::RangeProofError(
            "mismatched lengths for batch verification".into(),
        ));
    }
    let n = proofs.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    if n == 1 {
        // One job cannot be parallelised; skip the pool entirely rather than pay the hop.
        return Ok(vec![check_one(&proofs[0], &commitments[0], &generators[0])]);
    }
    Ok(verify_pool().install(|| {
        (0..n)
            .into_par_iter()
            .map(|i| check_one(&proofs[i], &commitments[i], &generators[i]))
            .collect()
    }))
}

/// Verify one proof, returning `None` when valid and the failure reason otherwise.
///
/// Mirrors the per-proof pyo3 binding exactly: a `min_value < 1` proof and a cryptographic failure
/// are both rejections (not errors), so they surface as the same message the Python loop used.
fn check_one(
    proof: &RangeProof,
    commitment: &PedersenCommitment,
    generator: &Generator,
) -> Option<String> {
    match verify_range_proof(proof, commitment, generator) {
        Ok(range) if range.start >= 1 => None,
        Ok(_) => Some("range proof verification failed".into()),
        Err(_) => Some("range proof verification failed".into()),
    }
}

/// Batch-verify multiple range proofs, failing on the first bad one.
///
/// Retained for existing callers; now parallel underneath.
pub fn batch_verify_range_proofs(
    proofs: &[RangeProof],
    commitments: &[PedersenCommitment],
    generators: &[Generator],
) -> Result<()> {
    for (i, outcome) in verify_range_proofs_parallel(proofs, commitments, generators)?
        .into_iter()
        .enumerate()
    {
        if let Some(msg) = outcome {
            return Err(HathorCtError::RangeProofError(format!(
                "proof {} failed: {}",
                i, msg
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
        // Zero-amount range proofs must be rejected (min_value=1).
        // With min_value=1, creating a range proof for amount=0 should fail.
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 0u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        // Creating a range proof with amount=0 and min_value=1 should fail
        let result = create_range_proof(amount, &blinding, &commitment, &gen, None, None);
        assert!(
            result.is_err(),
            "zero-amount range proof creation should fail with min_value=1"
        );
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
            let proof =
                create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
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
        let proof =
            create_range_proof(amount, &blinding, &commitment, &gen, Some(msg), None).unwrap();
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
        let proof = create_range_proof(
            amount,
            &blinding,
            &commitment,
            &gen,
            Some(msg),
            Some(&nonce),
        )
        .unwrap();

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
    fn test_proof_size_fits_fullnode_cap() {
        // A proof produced at the CONFIGURED bit width must fit the cap the fullnode deserializer
        // enforces, or the transaction cannot be parsed.
        //
        // Source of truth: `hathorlib/transaction/shielded_tx_output.py`
        //     MAX_RANGE_PROOF_SIZE = _env_capped_int('HATHOR_MAX_RANGE_PROOF_SIZE', 8192,
        //                                            hard_max=65535)
        // The 65535 ceiling is structural — `rp_len` is serialized as a 2-byte field.
        //
        // Mirror it here rather than guess: this constant previously read 3328, which was sized
        // for the 40-bit default of the time (3213 bytes + margin) and silently became wrong when
        // RANGE_PROOF_BITS moved to 64. Measured serialized sizes, worst case over representative
        // amounts:  32-bit 3213 · 40-bit 3213 · 48-bit 3853 · 64-bit 5070 — so every supported
        // width fits 8192, the tightest with ~3.1 KB to spare.
        //
        // The test deliberately does NOT pin HATHOR_RANGE_PROOF_BITS: cargo runs tests in threads
        // within one process, so setting an env var here would leak into other tests. Reading
        // whatever width is configured is also the more useful invariant.
        const MAX_RANGE_PROOF_SIZE: usize = 8192;

        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        // Use several representative amounts: small, medium, and large
        for &amount in &[1u64, 1000, 1_000_000_000, u64::MAX >> 24] {
            let commitment = create_commitment(amount, &blinding, &gen).unwrap();
            let proof =
                create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
            let serialized = serialize_range_proof(&proof);
            assert!(
                serialized.len() <= MAX_RANGE_PROOF_SIZE,
                "range proof for amount={} is {} bytes, exceeds cap of {} bytes",
                amount,
                serialized.len(),
                MAX_RANGE_PROOF_SIZE,
            );
        }
    }

    #[test]
    fn test_proof_size_is_constant() {
        // All proofs must be the same size regardless of amount, to prevent
        // leaking information about the committed value.
        let gen = htr_asset_tag();
        let mut sizes = Vec::new();
        for &amount in &[1u64, 42, 1000, 1_000_000_000, u64::MAX >> 24] {
            let blinding = Tweak::new(&mut rand::thread_rng());
            let commitment = create_commitment(amount, &blinding, &gen).unwrap();
            let proof =
                create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
            sizes.push(serialize_range_proof(&proof).len());
        }
        let first = sizes[0];
        for (i, &sz) in sizes.iter().enumerate() {
            assert_eq!(
                sz, first,
                "proof size varies: index {} is {} bytes but index 0 is {} bytes",
                i, sz, first,
            );
        }
    }

    #[test]
    fn test_rewind_wrong_nonce_fails() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 999u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        let nonce = SecretKey::new(&mut rand::thread_rng());
        let wrong_nonce = SecretKey::new(&mut rand::thread_rng());

        let proof =
            create_range_proof(amount, &blinding, &commitment, &gen, None, Some(&nonce)).unwrap();

        // Rewind with wrong nonce should fail
        let result = rewind_range_proof(&proof, &commitment, &wrong_nonce, &gen);
        assert!(result.is_err());
    }
}
