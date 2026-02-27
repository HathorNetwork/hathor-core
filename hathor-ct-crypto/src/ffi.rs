use pyo3::prelude::*;
use pyo3::types::PyBytes;
use secp256k1_zkp::{Generator, SecretKey, Tweak, ZERO_TWEAK};

use crate::error::HathorCtError;
use crate::types::COMMITMENT_SIZE;

fn to_py_err(e: HathorCtError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(e.to_string())
}

fn parse_tweak(bytes: &[u8]) -> PyResult<Tweak> {
    if bytes.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err("must be 32 bytes"));
    }
    Tweak::from_slice(bytes).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

fn parse_secret_key(bytes: &[u8]) -> PyResult<SecretKey> {
    if bytes.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err("must be 32 bytes"));
    }
    SecretKey::from_slice(bytes)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

fn parse_generator(bytes: &[u8]) -> PyResult<Generator> {
    if bytes.len() != 33 {
        return Err(pyo3::exceptions::PyValueError::new_err("must be 33 bytes"));
    }
    crate::generators::deserialize_generator(bytes).map_err(to_py_err)
}

/// Derive a deterministic NUMS generator for a token UID.
#[pyfunction]
fn derive_asset_tag(py: Python<'_>, token_uid: &[u8]) -> PyResult<PyObject> {
    if token_uid.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "token_uid must be 32 bytes",
        ));
    }
    let uid: [u8; 32] = token_uid
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("token_uid must be exactly 32 bytes"))?;
    let tag = crate::generators::derive_asset_tag(&uid).map_err(to_py_err)?;
    Ok(PyBytes::new_bound(py, &tag.serialize()).into())
}

/// Return the HTR asset tag (token_uid = [0; 32]).
#[pyfunction]
fn htr_asset_tag(py: Python<'_>) -> PyObject {
    let tag = crate::generators::htr_asset_tag();
    PyBytes::new_bound(py, &tag.serialize()).into()
}

/// Derive a raw Tag from token UID (for surjection proofs).
#[pyfunction]
fn derive_tag(py: Python<'_>, token_uid: &[u8]) -> PyResult<PyObject> {
    if token_uid.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "token_uid must be 32 bytes",
        ));
    }
    let uid: [u8; 32] = token_uid
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("token_uid must be exactly 32 bytes"))?;
    let tag = crate::generators::derive_tag(&uid).map_err(to_py_err)?;
    let tag_bytes: [u8; 32] = tag.into();
    Ok(PyBytes::new_bound(py, &tag_bytes).into())
}

/// Create a blinded asset commitment (Generator) from a Tag and blinding factor.
#[pyfunction]
fn create_asset_commitment(py: Python<'_>, tag_bytes: &[u8], r_asset: &[u8]) -> PyResult<PyObject> {
    if tag_bytes.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "tag must be 32 bytes (raw Tag)",
        ));
    }
    let tag = secp256k1_zkp::Tag::from(
        <[u8; 32]>::try_from(tag_bytes)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("tag must be exactly 32 bytes"))?,
    );
    let tweak = parse_tweak(r_asset)?;
    let commitment = crate::generators::create_asset_commitment(&tag, &tweak).map_err(to_py_err)?;
    Ok(PyBytes::new_bound(py, &commitment.serialize()).into())
}

/// Create a Pedersen commitment.
#[pyfunction]
fn create_commitment(
    py: Python<'_>,
    amount: u64,
    blinding: &[u8],
    generator: &[u8],
) -> PyResult<PyObject> {
    let bf = parse_tweak(blinding)?;
    let gen = parse_generator(generator)?;
    let c = crate::pedersen::create_commitment(amount, &bf, &gen).map_err(to_py_err)?;
    Ok(PyBytes::new_bound(py, &c.serialize()).into())
}

/// Create a trivial (zero-blinding) Pedersen commitment.
#[pyfunction]
fn create_trivial_commitment(py: Python<'_>, amount: u64, generator: &[u8]) -> PyResult<PyObject> {
    let gen = parse_generator(generator)?;
    let c = crate::pedersen::create_trivial_commitment(amount, &gen).map_err(to_py_err)?;
    Ok(PyBytes::new_bound(py, &c.serialize()).into())
}

/// Verify that sum of positive commitments equals sum of negative commitments.
#[pyfunction]
fn verify_commitments_sum(positive: Vec<Vec<u8>>, negative: Vec<Vec<u8>>) -> PyResult<bool> {
    let pos: Vec<_> = positive
        .iter()
        .map(|b| crate::pedersen::deserialize_commitment(b).map_err(to_py_err))
        .collect::<PyResult<Vec<_>>>()?;
    let neg: Vec<_> = negative
        .iter()
        .map(|b| crate::pedersen::deserialize_commitment(b).map_err(to_py_err))
        .collect::<PyResult<Vec<_>>>()?;
    Ok(crate::pedersen::verify_commitments_sum(&pos, &neg))
}

/// Create a Bulletproof range proof.
///
/// If `nonce` is provided (32 bytes), it is used as the nonce key, enabling
/// `rewind_range_proof` to recover the committed values. If None, a random nonce is used.
#[pyfunction]
#[pyo3(signature = (amount, blinding, commitment, generator, message=None, nonce=None))]
fn create_range_proof(
    py: Python<'_>,
    amount: u64,
    blinding: &[u8],
    commitment: &[u8],
    generator: &[u8],
    message: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> PyResult<PyObject> {
    let bf = parse_tweak(blinding)?;
    let comm = crate::pedersen::deserialize_commitment(commitment).map_err(to_py_err)?;
    let gen = parse_generator(generator)?;
    let nonce_key = nonce.map(|n| parse_secret_key(n)).transpose()?;
    let proof = crate::rangeproof::create_range_proof(
        amount, &bf, &comm, &gen, message, nonce_key.as_ref(),
    )
    .map_err(to_py_err)?;
    Ok(PyBytes::new_bound(py, &proof.serialize()).into())
}

/// Rewind a Bulletproof range proof to recover the committed value, blinding factor, and message.
///
/// Requires the same nonce key that was used when creating the proof.
/// Returns a tuple (value: int, blinding_factor: bytes, message: bytes).
#[pyfunction]
fn rewind_range_proof(
    py: Python<'_>,
    proof: &[u8],
    commitment: &[u8],
    nonce: &[u8],
    generator: &[u8],
) -> PyResult<PyObject> {
    let p = crate::rangeproof::deserialize_range_proof(proof).map_err(to_py_err)?;
    let c = crate::pedersen::deserialize_commitment(commitment).map_err(to_py_err)?;
    let sk = parse_secret_key(nonce)?;
    let gen = parse_generator(generator)?;
    let (value, blinding, message) =
        crate::rangeproof::rewind_range_proof(&p, &c, &sk, &gen).map_err(to_py_err)?;
    Ok((
        value,
        PyBytes::new_bound(py, blinding.as_ref()),
        PyBytes::new_bound(py, &message),
    )
        .into_py(py))
}

/// Verify a Bulletproof range proof.
///
/// Returns True if the proof is valid, False if cryptographic verification fails.
/// Raises ValueError if deserialization of any input fails.
/// Rejects proofs where the proven minimum value is less than 1 (VULN-005).
#[pyfunction]
fn verify_range_proof(proof: &[u8], commitment: &[u8], generator: &[u8]) -> PyResult<bool> {
    let p = crate::rangeproof::deserialize_range_proof(proof).map_err(to_py_err)?;
    let c = crate::pedersen::deserialize_commitment(commitment).map_err(to_py_err)?;
    let gen = parse_generator(generator)?;
    match crate::rangeproof::verify_range_proof(&p, &c, &gen) {
        Ok(range) => {
            if range.start < 1 {
                return Ok(false); // Reject zero-amount proofs (VULN-005)
            }
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// Validate that bytes represent a valid Pedersen commitment (curve point).
///
/// Returns True if the bytes can be deserialized as a valid commitment, False otherwise.
/// VULN-007: Prevents invalid curve points from passing commitment validation.
#[pyfunction]
fn validate_commitment(data: &[u8]) -> bool {
    if data.len() != 33 {
        return false;
    }
    crate::pedersen::deserialize_commitment(data).is_ok()
}

/// Validate that bytes represent a valid generator (curve point).
///
/// Returns True if the bytes can be deserialized as a valid generator, False otherwise.
/// VULN-007: Prevents invalid curve points from passing generator validation.
#[pyfunction]
fn validate_generator(data: &[u8]) -> bool {
    if data.len() != 33 {
        return false;
    }
    crate::generators::deserialize_generator(data).is_ok()
}

/// Create a surjection proof.
///
/// * `codomain_tag` - 32 bytes raw Tag for the output
/// * `codomain_blinding_factor` - 32 bytes Tweak for the output generator
/// * `domain` - list of (blinded_generator_33bytes, raw_tag_32bytes, blinding_factor_32bytes)
#[pyfunction]
fn create_surjection_proof(
    py: Python<'_>,
    codomain_tag: &[u8],
    codomain_blinding_factor: &[u8],
    domain: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
) -> PyResult<PyObject> {
    if codomain_tag.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "codomain_tag must be 32 bytes",
        ));
    }
    let ct = secp256k1_zkp::Tag::from(
        <[u8; 32]>::try_from(codomain_tag)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("codomain_tag must be exactly 32 bytes"))?,
    );
    let cbf = parse_tweak(codomain_blinding_factor)?;

    let domain_vec: Vec<(Generator, secp256k1_zkp::Tag, Tweak)> = domain
        .iter()
        .map(|(gen_bytes, tag_bytes, bf_bytes)| {
            let gen = parse_generator(gen_bytes)?;
            if tag_bytes.len() != 32 {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "tag must be 32 bytes",
                ));
            }
            let tag = secp256k1_zkp::Tag::from(
                <[u8; 32]>::try_from(tag_bytes.as_slice())
                    .map_err(|_| pyo3::exceptions::PyValueError::new_err("tag must be exactly 32 bytes"))?,
            );
            let bf = parse_tweak(bf_bytes)?;
            Ok((gen, tag, bf))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let proof =
        crate::surjection::create_surjection_proof(&ct, &cbf, &domain_vec).map_err(to_py_err)?;
    Ok(PyBytes::new_bound(py, &proof.serialize()).into())
}

/// Verify a surjection proof.
///
/// Returns True if the proof is valid, False if cryptographic verification fails.
/// Raises ValueError if deserialization of any input fails.
#[pyfunction]
fn verify_surjection_proof(proof: &[u8], codomain: &[u8], domain: Vec<Vec<u8>>) -> PyResult<bool> {
    let p = crate::surjection::deserialize_surjection_proof(proof).map_err(to_py_err)?;
    let codomain_gen = parse_generator(codomain)?;
    let domain_gens: Vec<Generator> = domain
        .iter()
        .map(|b| parse_generator(b))
        .collect::<PyResult<Vec<_>>>()?;
    match crate::surjection::verify_surjection_proof(&p, &codomain_gen, &domain_gens) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify the homomorphic balance equation.
#[pyfunction]
fn verify_balance(
    transparent_inputs: Vec<(u64, Vec<u8>)>,
    shielded_inputs: Vec<Vec<u8>>,
    transparent_outputs: Vec<(u64, Vec<u8>)>,
    shielded_outputs: Vec<Vec<u8>>,
) -> PyResult<bool> {
    let mut inputs = Vec::new();
    for (amount, token_uid) in &transparent_inputs {
        let uid: [u8; 32] = token_uid
            .as_slice()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("token_uid must be 32 bytes"))?;
        inputs.push(crate::balance::BalanceEntry::Transparent {
            amount: *amount,
            token_uid: uid,
        });
    }
    for cb in &shielded_inputs {
        let c = crate::pedersen::deserialize_commitment(cb).map_err(to_py_err)?;
        inputs.push(crate::balance::BalanceEntry::Shielded {
            value_commitment: c,
        });
    }

    let mut outputs = Vec::new();
    for (amount, token_uid) in &transparent_outputs {
        let uid: [u8; 32] = token_uid
            .as_slice()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("token_uid must be 32 bytes"))?;
        outputs.push(crate::balance::BalanceEntry::Transparent {
            amount: *amount,
            token_uid: uid,
        });
    }
    for cb in &shielded_outputs {
        let c = crate::pedersen::deserialize_commitment(cb).map_err(to_py_err)?;
        outputs.push(crate::balance::BalanceEntry::Shielded {
            value_commitment: c,
        });
    }

    crate::balance::verify_balance(&inputs, &outputs)
        .map(|()| true)
        .or_else(|e| match e {
            // Balance mismatch is a verification failure, not an error
            HathorCtError::BalanceError(_) => Ok(false),
            // Other errors (e.g., deserialization) should propagate
            other => Err(to_py_err(other)),
        })
}

/// Compute the balancing blinding factor for the last output.
#[pyfunction]
fn compute_balancing_blinding_factor(
    py: Python<'_>,
    value: u64,
    generator_blinding_factor: &[u8],
    inputs: Vec<(u64, Vec<u8>, Vec<u8>)>,
    other_outputs: Vec<(u64, Vec<u8>, Vec<u8>)>,
) -> PyResult<PyObject> {
    let gbf = parse_tweak(generator_blinding_factor)?;

    let in_entries: Vec<(u64, Tweak, Tweak)> = inputs
        .iter()
        .map(|(v, vbf, gbf)| Ok((*v, parse_tweak(vbf)?, parse_tweak(gbf)?)))
        .collect::<PyResult<Vec<_>>>()?;

    let out_entries: Vec<(u64, Tweak, Tweak)> = other_outputs
        .iter()
        .map(|(v, vbf, gbf)| Ok((*v, parse_tweak(vbf)?, parse_tweak(gbf)?)))
        .collect::<PyResult<Vec<_>>>()?;

    let result =
        crate::balance::compute_balancing_blinding_factor(value, &gbf, &in_entries, &out_entries)
            .map_err(to_py_err)?;

    Ok(PyBytes::new_bound(py, result.as_ref()).into())
}

/// The Python module definition.
#[pymodule]
fn hathor_ct_crypto(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(derive_asset_tag, m)?)?;
    m.add_function(wrap_pyfunction!(htr_asset_tag, m)?)?;
    m.add_function(wrap_pyfunction!(derive_tag, m)?)?;
    m.add_function(wrap_pyfunction!(create_asset_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(create_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(create_trivial_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(verify_commitments_sum, m)?)?;
    m.add_function(wrap_pyfunction!(create_range_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_range_proof, m)?)?;
    m.add_function(wrap_pyfunction!(rewind_range_proof, m)?)?;
    m.add_function(wrap_pyfunction!(validate_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(validate_generator, m)?)?;
    m.add_function(wrap_pyfunction!(create_surjection_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_surjection_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_balance, m)?)?;
    m.add_function(wrap_pyfunction!(compute_balancing_blinding_factor, m)?)?;

    m.add("COMMITMENT_SIZE", COMMITMENT_SIZE)?;
    m.add("GENERATOR_SIZE", crate::types::GENERATOR_SIZE)?;
    m.add("ZERO_TWEAK", PyBytes::new_bound(py, ZERO_TWEAK.as_ref()))?;

    Ok(())
}
