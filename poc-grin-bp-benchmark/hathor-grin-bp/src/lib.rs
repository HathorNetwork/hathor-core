//! PyO3 bindings exposing grin_secp256k1zkp's original Bulletproofs to the
//! Python benchmarks.
//!
//! Mirrors the function shapes used by `hathor.crypto.shielded.range_proof` so
//! the existing benchmark scripts can swap modules with minimal changes, and
//! adds `batch_verify_range_proofs` / `multi_create_proofs` for the batch-verify
//! sweep that is the unique payoff of `grin_secp256k1zkp` over the in-tree
//! Borromean path.

use std::sync::OnceLock;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use secp256k1zkp::constants;
use secp256k1zkp::key::SecretKey;
use secp256k1zkp::pedersen::{Commitment, RangeProof};
use secp256k1zkp::{ContextFlag, Secp256k1};

const COMMITMENT_BYTES: usize = 33;

fn secp() -> &'static Secp256k1 {
    static CTX: OnceLock<Secp256k1> = OnceLock::new();
    CTX.get_or_init(|| Secp256k1::with_caps(ContextFlag::Commit))
}

fn secret_from_bytes(bytes: &[u8]) -> PyResult<SecretKey> {
    if bytes.len() != 32 {
        return Err(PyValueError::new_err("blinding/scalar must be 32 bytes"));
    }
    SecretKey::from_slice(secp(), bytes)
        .map_err(|e| PyValueError::new_err(format!("invalid scalar: {e:?}")))
}

fn commitment_from_bytes(bytes: &[u8]) -> PyResult<Commitment> {
    if bytes.len() != COMMITMENT_BYTES {
        return Err(PyValueError::new_err(format!(
            "commitment must be {COMMITMENT_BYTES} bytes"
        )));
    }
    let mut buf = [0u8; COMMITMENT_BYTES];
    buf.copy_from_slice(bytes);
    Ok(Commitment(buf))
}

fn rangeproof_from_bytes(bytes: &[u8]) -> PyResult<RangeProof> {
    if bytes.len() > constants::MAX_PROOF_SIZE {
        return Err(PyValueError::new_err(format!(
            "proof too long: {} > MAX_PROOF_SIZE={}",
            bytes.len(),
            constants::MAX_PROOF_SIZE
        )));
    }
    let mut arr = [0u8; constants::MAX_PROOF_SIZE];
    arr[..bytes.len()].copy_from_slice(bytes);
    Ok(RangeProof {
        proof: arr,
        plen: bytes.len(),
    })
}

// ---------------------------------------------------------------------------
// PyO3 surface
// ---------------------------------------------------------------------------

/// Pedersen value commitment: `value*H + blind*G` using libsecp's `H`.
///
/// `generator` is accepted for signature parity with the asset-blinded API in
/// `hathor.crypto.shielded.commitment`, but it is ignored — grin's `commit`
/// uses the fixed libsecp value generator.
#[pyfunction]
#[pyo3(signature = (amount, blinding, _generator=None))]
fn create_commitment(
    py: Python<'_>,
    amount: u64,
    blinding: &[u8],
    _generator: Option<&[u8]>,
) -> PyResult<PyObject> {
    let blind = secret_from_bytes(blinding)?;
    let c = secp()
        .commit(amount, blind)
        .map_err(|e| PyValueError::new_err(format!("commit failed: {e:?}")))?;
    Ok(PyBytes::new_bound(py, &c.0).into())
}

/// Build a single-output original Bulletproof range proof for `amount`.
///
/// Auxiliary `commitment` / `generator` / `message` are accepted for signature
/// parity with the Borromean range-proof API used by `poc-shielded-benchmark/`,
/// but are not consumed here. `nonce`, if supplied, is used as both the rewind
/// and private nonce — that is benchmark-only behavior and MUST NOT be copied
/// into production code, which has to pass independent rewind/private nonces.
#[pyfunction]
#[pyo3(signature = (amount, blinding, _commitment=None, _generator=None, _message=None, nonce=None))]
fn create_range_proof(
    py: Python<'_>,
    amount: u64,
    blinding: &[u8],
    _commitment: Option<&[u8]>,
    _generator: Option<&[u8]>,
    _message: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> PyResult<PyObject> {
    let blind = secret_from_bytes(blinding)?;
    let n = match nonce {
        Some(nb) => secret_from_bytes(nb)?,
        None => blind.clone(),
    };
    let proof = secp().bullet_proof(amount, blind, n.clone(), n, None, None);
    Ok(PyBytes::new_bound(py, proof.bytes()).into())
}

/// Single-proof verify. Equivalent to `secp256k1_bulletproof_rangeproof_verify`
/// over a single commitment/proof pair.
#[pyfunction]
#[pyo3(signature = (proof, commitment, _generator=None))]
fn verify_range_proof(
    proof: &[u8],
    commitment: &[u8],
    _generator: Option<&[u8]>,
) -> PyResult<bool> {
    let c = commitment_from_bytes(commitment)?;
    let p = rangeproof_from_bytes(proof)?;
    Ok(secp().verify_bullet_proof(c, p, None).is_ok())
}

/// Real batched verification: one `secp256k1_bulletproof_rangeproof_verify_multi`
/// call across all (commitment, proof) pairs. This is the API the in-tree
/// `batch_verify_range_proofs` in `hathor-ct-crypto/src/rangeproof.rs` only
/// pretends to expose — there it's a sequential loop with no aggregation.
#[pyfunction]
fn batch_verify_range_proofs(proofs: Vec<Vec<u8>>, commitments: Vec<Vec<u8>>) -> PyResult<bool> {
    if proofs.len() != commitments.len() {
        return Err(PyValueError::new_err(
            "proofs/commitments length mismatch",
        ));
    }
    if proofs.is_empty() {
        return Ok(true);
    }
    let commits: Result<Vec<_>, _> =
        commitments.iter().map(|b| commitment_from_bytes(b)).collect();
    let commits = commits?;
    let proof_objs: Result<Vec<_>, _> =
        proofs.iter().map(|b| rangeproof_from_bytes(b)).collect();
    let proof_objs = proof_objs?;
    Ok(secp()
        .verify_bullet_proof_multi(commits, proof_objs, None)
        .is_ok())
}

/// Serial create of `K` single-output proofs.
///
/// NOTE: this is NOT an aggregated multi-output proof. The C library's
/// `secp256k1_bulletproof_rangeproof_prove` does accept a `values`+`blinds`
/// vector and produce a single aggregated proof, but `grin_secp256k1zkp 0.7`
/// only exposes the single-output Rust signature (Grin itself only uses
/// single-output proofs). Exposing aggregated prove would require dropping
/// to the `-sys` layer or a fork — out of scope for this POC. This function
/// is the honest baseline: K independent prove calls, returning K independent
/// proof byte strings, with one round-trip across the FFI boundary.
#[pyfunction]
fn multi_create_proofs(
    py: Python<'_>,
    amounts: Vec<u64>,
    blindings: Vec<Vec<u8>>,
) -> PyResult<Vec<PyObject>> {
    if amounts.len() != blindings.len() {
        return Err(PyValueError::new_err("amounts/blindings length mismatch"));
    }
    let mut out = Vec::with_capacity(amounts.len());
    for (v, b) in amounts.iter().zip(blindings.iter()) {
        let blind = secret_from_bytes(b)?;
        let proof = secp().bullet_proof(*v, blind.clone(), blind.clone(), blind, None, None);
        out.push(PyBytes::new_bound(py, proof.bytes()).into());
    }
    Ok(out)
}

/// Diagnostic: produce one proof for amount=2^60 and return its byte length.
#[pyfunction]
fn proof_size_bytes() -> PyResult<usize> {
    let blind = SecretKey::from_slice(secp(), &[1u8; 32])
        .map_err(|e| PyValueError::new_err(format!("seed scalar invalid: {e:?}")))?;
    let proof = secp().bullet_proof(
        1u64 << 60,
        blind.clone(),
        blind.clone(),
        blind,
        None,
        None,
    );
    Ok(proof.plen)
}

#[pymodule]
fn hathor_grin_bp(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(create_range_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_range_proof, m)?)?;
    m.add_function(wrap_pyfunction!(batch_verify_range_proofs, m)?)?;
    m.add_function(wrap_pyfunction!(multi_create_proofs, m)?)?;
    m.add_function(wrap_pyfunction!(proof_size_bytes, m)?)?;
    Ok(())
}
