use pyo3::prelude::*;
use pyo3::types::PyBytes;
use secp256k1_zkp::{Generator, SecretKey, Tweak, ZERO_TWEAK};

use htr_lib::error::HathorCtError;
use htr_lib::types::COMMITMENT_SIZE;

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
    SecretKey::from_slice(bytes).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

fn parse_generator(bytes: &[u8]) -> PyResult<Generator> {
    if bytes.len() != 33 {
        return Err(pyo3::exceptions::PyValueError::new_err("must be 33 bytes"));
    }
    htr_lib::generators::deserialize_generator(bytes).map_err(to_py_err)
}

/// Derive a deterministic NUMS generator for a token UID.
#[pyfunction]
fn derive_asset_tag(py: Python<'_>, token_uid: &[u8]) -> PyResult<Py<PyAny>> {
    if token_uid.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "token_uid must be 32 bytes",
        ));
    }
    let uid: [u8; 32] = token_uid.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("token_uid must be exactly 32 bytes")
    })?;
    let tag = htr_lib::generators::derive_asset_tag(&uid).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &tag.serialize()).into_any().unbind())
}

/// Return the HTR asset tag (token_uid = [0; 32]).
#[pyfunction]
fn htr_asset_tag(py: Python<'_>) -> Py<PyAny> {
    let tag = htr_lib::generators::htr_asset_tag();
    PyBytes::new(py, &tag.serialize()).into_any().unbind()
}

/// Derive a raw Tag from token UID (for surjection proofs).
#[pyfunction]
fn derive_tag(py: Python<'_>, token_uid: &[u8]) -> PyResult<Py<PyAny>> {
    if token_uid.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "token_uid must be 32 bytes",
        ));
    }
    let uid: [u8; 32] = token_uid.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("token_uid must be exactly 32 bytes")
    })?;
    let tag = htr_lib::generators::derive_tag(&uid).map_err(to_py_err)?;
    let tag_bytes: [u8; 32] = tag.into();
    Ok(PyBytes::new(py, &tag_bytes).into_any().unbind())
}

/// Create a blinded asset commitment (Generator) from a Tag and blinding factor.
#[pyfunction]
fn create_asset_commitment(
    py: Python<'_>,
    tag_bytes: &[u8],
    r_asset: &[u8],
) -> PyResult<Py<PyAny>> {
    if tag_bytes.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "tag must be 32 bytes (raw Tag)",
        ));
    }
    let tag =
        secp256k1_zkp::Tag::from(<[u8; 32]>::try_from(tag_bytes).map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("tag must be exactly 32 bytes")
        })?);
    let tweak = parse_tweak(r_asset)?;
    let commitment =
        htr_lib::generators::create_asset_commitment(&tag, &tweak).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &commitment.serialize())
        .into_any()
        .unbind())
}

/// Create a Pedersen commitment.
#[pyfunction]
fn create_commitment(
    py: Python<'_>,
    amount: u64,
    blinding: &[u8],
    generator: &[u8],
) -> PyResult<Py<PyAny>> {
    let bf = parse_tweak(blinding)?;
    let genr = parse_generator(generator)?;
    let c = htr_lib::pedersen::create_commitment(amount, &bf, &genr).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &c.serialize()).into_any().unbind())
}

/// Create a trivial (zero-blinding) Pedersen commitment.
#[pyfunction]
fn create_trivial_commitment(py: Python<'_>, amount: u64, generator: &[u8]) -> PyResult<Py<PyAny>> {
    let genr = parse_generator(generator)?;
    let c = htr_lib::pedersen::create_trivial_commitment(amount, &genr).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &c.serialize()).into_any().unbind())
}

/// Verify that sum of positive commitments equals sum of negative commitments.
#[pyfunction]
fn verify_commitments_sum(positive: Vec<Vec<u8>>, negative: Vec<Vec<u8>>) -> PyResult<bool> {
    let pos: Vec<_> = positive
        .iter()
        .map(|b| htr_lib::pedersen::deserialize_commitment(b).map_err(to_py_err))
        .collect::<PyResult<Vec<_>>>()?;
    let neg: Vec<_> = negative
        .iter()
        .map(|b| htr_lib::pedersen::deserialize_commitment(b).map_err(to_py_err))
        .collect::<PyResult<Vec<_>>>()?;
    Ok(htr_lib::pedersen::verify_commitments_sum(&pos, &neg))
}

/// Create a Borromean range proof.
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
) -> PyResult<Py<PyAny>> {
    let bf = parse_tweak(blinding)?;
    let comm = htr_lib::pedersen::deserialize_commitment(commitment).map_err(to_py_err)?;
    let genr = parse_generator(generator)?;
    let nonce_key = nonce.map(parse_secret_key).transpose()?;
    let proof = htr_lib::rangeproof::create_range_proof(
        amount,
        &bf,
        &comm,
        &genr,
        message,
        nonce_key.as_ref(),
    )
    .map_err(to_py_err)?;
    Ok(PyBytes::new(py, &proof.serialize()).into_any().unbind())
}

/// Rewind a Borromean range proof to recover the committed value, blinding factor, and message.
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
) -> PyResult<Py<PyAny>> {
    let p = htr_lib::rangeproof::deserialize_range_proof(proof).map_err(to_py_err)?;
    let c = htr_lib::pedersen::deserialize_commitment(commitment).map_err(to_py_err)?;
    let sk = parse_secret_key(nonce)?;
    let genr = parse_generator(generator)?;
    let (value, blinding, message) =
        htr_lib::rangeproof::rewind_range_proof(&p, &c, &sk, &genr).map_err(to_py_err)?;
    let result = (
        value,
        PyBytes::new(py, blinding.as_ref()),
        PyBytes::new(py, &message),
    )
        .into_pyobject(py)?;
    Ok(result.into_any().unbind())
}

/// Verify a Borromean range proof.
///
/// Returns True if the proof is valid, False if cryptographic verification fails.
/// Raises ValueError if deserialization of any input fails.
/// Rejects proofs where the proven minimum value is less than 1.
#[pyfunction]
fn verify_range_proof(proof: &[u8], commitment: &[u8], generator: &[u8]) -> PyResult<bool> {
    let p = htr_lib::rangeproof::deserialize_range_proof(proof).map_err(to_py_err)?;
    let c = htr_lib::pedersen::deserialize_commitment(commitment).map_err(to_py_err)?;
    let genr = parse_generator(generator)?;
    match htr_lib::rangeproof::verify_range_proof(&p, &c, &genr) {
        Ok(range) => {
            if range.start < 1 {
                return Ok(false); // Reject zero-amount proofs
            }
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// Validate that bytes represent a valid Pedersen commitment (curve point).
///
/// Returns True if the bytes can be deserialized as a valid commitment, False otherwise.
/// Prevents invalid curve points from passing commitment validation.
#[pyfunction]
fn validate_commitment(data: &[u8]) -> bool {
    if data.len() != 33 {
        return false;
    }
    htr_lib::pedersen::deserialize_commitment(data).is_ok()
}

/// Validate that bytes represent a valid generator (curve point).
///
/// Returns True if the bytes can be deserialized as a valid generator, False otherwise.
/// Prevents invalid curve points from passing generator validation.
#[pyfunction]
fn validate_generator(data: &[u8]) -> bool {
    if data.len() != 33 {
        return false;
    }
    htr_lib::generators::deserialize_generator(data).is_ok()
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
) -> PyResult<Py<PyAny>> {
    if codomain_tag.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "codomain_tag must be 32 bytes",
        ));
    }
    let ct = secp256k1_zkp::Tag::from(<[u8; 32]>::try_from(codomain_tag).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("codomain_tag must be exactly 32 bytes")
    })?);
    let cbf = parse_tweak(codomain_blinding_factor)?;

    let domain_vec: Vec<(Generator, secp256k1_zkp::Tag, Tweak)> = domain
        .iter()
        .map(|(gen_bytes, tag_bytes, bf_bytes)| {
            let genr = parse_generator(gen_bytes)?;
            if tag_bytes.len() != 32 {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "tag must be 32 bytes",
                ));
            }
            let tag =
                secp256k1_zkp::Tag::from(<[u8; 32]>::try_from(tag_bytes.as_slice()).map_err(
                    |_| pyo3::exceptions::PyValueError::new_err("tag must be exactly 32 bytes"),
                )?);
            let bf = parse_tweak(bf_bytes)?;
            Ok((genr, tag, bf))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let proof =
        htr_lib::surjection::create_surjection_proof(&ct, &cbf, &domain_vec).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &proof.serialize()).into_any().unbind())
}

/// Verify a surjection proof.
///
/// Returns True if the proof is valid, False if cryptographic verification fails.
/// Raises ValueError if deserialization of any input fails.
#[pyfunction]
fn verify_surjection_proof(proof: &[u8], codomain: &[u8], domain: Vec<Vec<u8>>) -> PyResult<bool> {
    let p = htr_lib::surjection::deserialize_surjection_proof(proof).map_err(to_py_err)?;
    let codomain_gen = parse_generator(codomain)?;
    let domain_gens: Vec<Generator> = domain
        .iter()
        .map(|b| parse_generator(b))
        .collect::<PyResult<Vec<_>>>()?;
    match htr_lib::surjection::verify_surjection_proof(&p, &codomain_gen, &domain_gens) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify the homomorphic balance equation.
#[pyfunction]
#[pyo3(signature = (
    transparent_inputs,
    shielded_inputs,
    transparent_outputs,
    shielded_outputs,
    excess_blinding_factor=None,
))]
fn verify_balance(
    transparent_inputs: Vec<(u64, Vec<u8>)>,
    shielded_inputs: Vec<Vec<u8>>,
    transparent_outputs: Vec<(u64, Vec<u8>)>,
    shielded_outputs: Vec<Vec<u8>>,
    excess_blinding_factor: Option<Vec<u8>>,
) -> PyResult<bool> {
    let mut inputs = Vec::new();
    for (amount, token_uid) in &transparent_inputs {
        let uid: [u8; 32] = token_uid
            .as_slice()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("token_uid must be 32 bytes"))?;
        inputs.push(htr_lib::balance::BalanceEntry::Transparent {
            amount: *amount,
            token_uid: uid,
        });
    }
    for cb in &shielded_inputs {
        let c = htr_lib::pedersen::deserialize_commitment(cb).map_err(to_py_err)?;
        inputs.push(htr_lib::balance::BalanceEntry::Shielded {
            value_commitment: c,
        });
    }

    let mut outputs = Vec::new();
    for (amount, token_uid) in &transparent_outputs {
        let uid: [u8; 32] = token_uid
            .as_slice()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("token_uid must be 32 bytes"))?;
        outputs.push(htr_lib::balance::BalanceEntry::Transparent {
            amount: *amount,
            token_uid: uid,
        });
    }
    for cb in &shielded_outputs {
        let c = htr_lib::pedersen::deserialize_commitment(cb).map_err(to_py_err)?;
        outputs.push(htr_lib::balance::BalanceEntry::Shielded {
            value_commitment: c,
        });
    }

    // Structural invariants on the excess blinding factor. These also live in
    // the Python verifier (which enforces them at the tx-header level), but we
    // re-check at the FFI boundary because the structured signature here
    // still separates shielded from transparent:
    //   - excess and shielded_outputs cannot coexist;
    //   - excess requires at least one shielded input (otherwise there's no
    //     sum(r_in)·G term to cancel, and the scalar is meaningless).
    let excess = match excess_blinding_factor {
        Some(bytes) => {
            if !shielded_outputs.is_empty() {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "excess_blinding_factor must be None when shielded_outputs is non-empty",
                ));
            }
            if shielded_inputs.is_empty() {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "excess_blinding_factor requires at least one shielded input",
                ));
            }
            Some(parse_tweak(&bytes)?)
        }
        None => None,
    };

    htr_lib::balance::verify_balance(&inputs, &outputs, excess)
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
) -> PyResult<Py<PyAny>> {
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
        htr_lib::balance::compute_balancing_blinding_factor(value, &gbf, &in_entries, &out_entries)
            .map_err(to_py_err)?;

    Ok(PyBytes::new(py, result.as_ref()).into_any().unbind())
}

/// Generate a random 32-byte blinding factor (valid secp256k1 scalar).
#[pyfunction]
fn generate_random_blinding_factor(py: Python<'_>) -> Py<PyAny> {
    let bf = htr_lib::ecdh::generate_random_blinding_factor();
    PyBytes::new(py, &bf).into_any().unbind()
}

/// Generate a fresh ephemeral secp256k1 key pair.
///
/// Returns (private_key_bytes: 32B, compressed_pubkey_bytes: 33B).
#[pyfunction]
fn generate_ephemeral_keypair(py: Python<'_>) -> PyResult<Py<PyAny>> {
    let (sk_bytes, pk_bytes) = htr_lib::ecdh::generate_ephemeral_keypair();
    let result = (PyBytes::new(py, &sk_bytes), PyBytes::new(py, &pk_bytes)).into_pyobject(py)?;
    Ok(result.into_any().unbind())
}

/// Compute ECDH shared secret: SHA256(version_byte || x_coordinate).
///
/// Uses libsecp256k1's standard ECDH derivation.
/// Returns 32-byte shared secret.
#[pyfunction]
fn derive_ecdh_shared_secret(
    py: Python<'_>,
    private_key: &[u8],
    peer_pubkey: &[u8],
) -> PyResult<Py<PyAny>> {
    let sk = htr_lib::ecdh::parse_secret_key(private_key).map_err(to_py_err)?;
    let pk = htr_lib::ecdh::parse_public_key(peer_pubkey).map_err(to_py_err)?;
    let secret = htr_lib::ecdh::derive_ecdh_shared_secret(&sk, &pk);
    Ok(PyBytes::new(py, &secret).into_any().unbind())
}

/// Derive a deterministic nonce from a shared secret.
///
/// nonce = SHA256("Hathor_CT_nonce_v1" || shared_secret)
/// Returns 32-byte nonce suitable for use as a range proof nonce key.
#[pyfunction]
fn derive_rewind_nonce(py: Python<'_>, shared_secret: &[u8]) -> PyResult<Py<PyAny>> {
    if shared_secret.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "shared_secret must be 32 bytes",
        ));
    }
    let secret: [u8; 32] = shared_secret
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("shared_secret conversion failed"))?;
    let nonce = htr_lib::ecdh::derive_rewind_nonce(&secret);
    Ok(PyBytes::new(py, &nonce).into_any().unbind())
}

/// Result of creating a shielded output with pre-computed blinding factors.
#[pyclass(frozen, get_all)]
struct CreatedShieldedOutput {
    ephemeral_pubkey: Py<PyBytes>,
    commitment: Py<PyBytes>,
    range_proof: Py<PyBytes>,
    blinding_factor: Py<PyBytes>,
    asset_commitment: Py<PyBytes>,
    asset_blinding_factor: Py<PyBytes>,
}

/// Create a FullShielded output with both value blinding factor and asset blinding factor
/// provided externally. This is needed for the last output in a FullShielded transaction
/// where the balance equation requires pre-computing the vbf using a known abf.
#[pyfunction]
fn create_shielded_output_with_both_blindings(
    py: Python<'_>,
    value: u64,
    recipient_pubkey: &[u8],
    token_uid: &[u8],
    value_blinding_factor: &[u8],
    asset_blinding_factor: &[u8],
) -> PyResult<CreatedShieldedOutput> {
    if token_uid.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "token_uid must be 32 bytes",
        ));
    }
    if value_blinding_factor.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "value_blinding_factor must be 32 bytes",
        ));
    }
    if asset_blinding_factor.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "asset_blinding_factor must be 32 bytes",
        ));
    }

    let tuid: [u8; 32] = token_uid
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("token_uid conversion failed"))?;
    let vbf: [u8; 32] = value_blinding_factor.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("value_blinding_factor conversion failed")
    })?;
    let abf: [u8; 32] = asset_blinding_factor.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("asset_blinding_factor conversion failed")
    })?;

    let result =
        htr_lib::ecdh::create_full_shielded_output(value, recipient_pubkey, &tuid, &vbf, &abf)
            .map_err(to_py_err)?;

    Ok(CreatedShieldedOutput {
        ephemeral_pubkey: PyBytes::new(py, &result.ephemeral_pubkey).unbind(),
        commitment: PyBytes::new(py, &result.commitment).unbind(),
        range_proof: PyBytes::new(py, &result.range_proof).unbind(),
        blinding_factor: PyBytes::new(py, &result.value_blinding_factor).unbind(),
        asset_commitment: PyBytes::new(py, &result.asset_commitment).unbind(),
        asset_blinding_factor: PyBytes::new(py, &result.asset_blinding_factor).unbind(),
    })
}

/// Result of creating an AmountShielded output (amount hidden, token visible).
#[pyclass(frozen, get_all)]
struct CreatedAmountShieldedOutput {
    ephemeral_pubkey: Py<PyBytes>,
    commitment: Py<PyBytes>,
    range_proof: Py<PyBytes>,
    blinding_factor: Py<PyBytes>,
}

/// Create an AmountShielded output (amount hidden, token visible).
///
/// Uses `derive_asset_tag(token_uid)` as the unblinded generator.
#[pyfunction]
fn create_amount_shielded_output(
    py: Python<'_>,
    value: u64,
    recipient_pubkey: &[u8],
    token_uid: &[u8],
    value_blinding_factor: &[u8],
) -> PyResult<CreatedAmountShieldedOutput> {
    if token_uid.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "token_uid must be 32 bytes",
        ));
    }
    if value_blinding_factor.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "value_blinding_factor must be 32 bytes",
        ));
    }

    let tuid: [u8; 32] = token_uid
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("token_uid conversion failed"))?;
    let vbf: [u8; 32] = value_blinding_factor.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("value_blinding_factor conversion failed")
    })?;

    let result = htr_lib::ecdh::create_amount_shielded_output(value, recipient_pubkey, &tuid, &vbf)
        .map_err(to_py_err)?;

    Ok(CreatedAmountShieldedOutput {
        ephemeral_pubkey: PyBytes::new(py, &result.ephemeral_pubkey).unbind(),
        commitment: PyBytes::new(py, &result.commitment).unbind(),
        range_proof: PyBytes::new(py, &result.range_proof).unbind(),
        blinding_factor: PyBytes::new(py, &result.value_blinding_factor).unbind(),
    })
}

/// Result of rewinding an AmountShielded output.
#[pyclass(frozen, get_all)]
struct RewoundAmountShieldedOutput {
    value: u64,
    blinding_factor: Py<PyBytes>,
}

/// Rewind an AmountShielded output to recover value and blinding factor.
#[pyfunction]
fn rewind_amount_shielded_output(
    py: Python<'_>,
    private_key: &[u8],
    ephemeral_pubkey: &[u8],
    commitment: &[u8],
    range_proof: &[u8],
    token_uid: &[u8],
) -> PyResult<RewoundAmountShieldedOutput> {
    if token_uid.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "token_uid must be 32 bytes",
        ));
    }
    let tuid: [u8; 32] = token_uid
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("token_uid conversion failed"))?;

    let result = htr_lib::ecdh::rewind_amount_shielded_output(
        private_key,
        ephemeral_pubkey,
        commitment,
        range_proof,
        &tuid,
    )
    .map_err(to_py_err)?;

    Ok(RewoundAmountShieldedOutput {
        value: result.value,
        blinding_factor: PyBytes::new(py, &result.blinding_factor).unbind(),
    })
}

/// Result of rewinding a FullShielded output.
#[pyclass(frozen, get_all)]
struct RewoundFullShieldedOutput {
    value: u64,
    blinding_factor: Py<PyBytes>,
    token_uid: Py<PyBytes>,
    asset_blinding_factor: Py<PyBytes>,
}

/// Rewind a FullShielded output to recover value, blinding factor, token UID and asset blinding.
#[pyfunction]
fn rewind_full_shielded_output(
    py: Python<'_>,
    private_key: &[u8],
    ephemeral_pubkey: &[u8],
    commitment: &[u8],
    range_proof: &[u8],
    asset_commitment: &[u8],
) -> PyResult<RewoundFullShieldedOutput> {
    let result = htr_lib::ecdh::rewind_full_shielded_output(
        private_key,
        ephemeral_pubkey,
        commitment,
        range_proof,
        asset_commitment,
    )
    .map_err(to_py_err)?;

    Ok(RewoundFullShieldedOutput {
        value: result.value,
        blinding_factor: PyBytes::new(py, &result.blinding_factor).unbind(),
        token_uid: PyBytes::new(py, &result.token_uid).unbind(),
        asset_blinding_factor: PyBytes::new(py, &result.asset_blinding_factor).unbind(),
    })
}

/// Populate `m` with the confidential-transaction crypto functions, classes and constants.
fn register_items(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
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
    m.add_function(wrap_pyfunction!(generate_random_blinding_factor, m)?)?;
    m.add_function(wrap_pyfunction!(generate_ephemeral_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(derive_ecdh_shared_secret, m)?)?;
    m.add_function(wrap_pyfunction!(derive_rewind_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(
        create_shielded_output_with_both_blindings,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(create_amount_shielded_output, m)?)?;
    m.add_function(wrap_pyfunction!(rewind_amount_shielded_output, m)?)?;
    m.add_function(wrap_pyfunction!(rewind_full_shielded_output, m)?)?;
    m.add_class::<CreatedShieldedOutput>()?;
    m.add_class::<CreatedAmountShieldedOutput>()?;
    m.add_class::<RewoundAmountShieldedOutput>()?;
    m.add_class::<RewoundFullShieldedOutput>()?;

    m.add("COMMITMENT_SIZE", COMMITMENT_SIZE)?;
    m.add("GENERATOR_SIZE", htr_lib::types::GENERATOR_SIZE)?;
    m.add("ZERO_TWEAK", PyBytes::new(py, ZERO_TWEAK.as_ref()))?;

    Ok(())
}

/// Register the `shielded` submodule on the parent `htr_lib` module.
pub(crate) fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = parent.py();
    let m = PyModule::new(py, "shielded")?;
    register_items(&m)?;
    parent.add_submodule(&m)?;
    Ok(())
}
