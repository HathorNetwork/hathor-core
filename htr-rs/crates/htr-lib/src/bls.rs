//! BLS12-381 signatures for Hathor's two-tier finality, backed by `blst`.
//!
//! Layout is **min-pubkey-size** (`blst::min_pk`): public keys are 48-byte compressed G1 points and
//! signatures are 96-byte compressed G2 points, matching the `py_ecc` `G2ProofOfPossession` backend
//! this replaces (same ciphersuite, so signatures and proofs-of-possession are byte-for-byte
//! interchangeable). All validators sign the *same* per-transaction message, so a quorum's votes
//! aggregate into one signature verified with a single `FastAggregateVerify`; that same-message
//! aggregation is only rogue-key-safe because every committee key carries a verified
//! proof-of-possession, hence the proof-of-possession ciphersuite.
//!
//! Signature/key parsing comes from untrusted network data, so verification enables subgroup checks
//! (`sig_groupcheck` / `pk_validate`) and every malformed input is rejected as a verification failure
//! rather than an error.

use blst::BLST_ERROR;
use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Compressed private-key (scalar) length, in bytes.
const SECRET_KEY_LEN: usize = 32;
/// Compressed G1 public-key length, in bytes.
const PUBLIC_KEY_LEN: usize = 48;
/// Compressed G2 signature (and proof-of-possession) length, in bytes.
const SIGNATURE_LEN: usize = 96;

/// Domain-separation tag for ordinary signatures (proof-of-possession ciphersuite, signatures in G2).
const DST_SIG: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Domain-separation tag for proofs-of-possession (distinct from `DST_SIG` so a PoP can never be
/// replayed as an ordinary signature, or vice versa).
const DST_POP: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn to_pyerr(error: BLST_ERROR) -> PyErr {
    PyValueError::new_err(format!("bls error: {error:?}"))
}

/// Derive a private key from input key material (`ikm` must be >= 32 bytes of entropy), returning its
/// 32 big-endian scalar bytes.
fn keygen(ikm: &[u8]) -> Result<[u8; SECRET_KEY_LEN], BLST_ERROR> {
    let secret_key = SecretKey::key_gen(ikm, &[])?;
    Ok(secret_key.to_bytes())
}

/// Return the compressed public key for a private key.
fn sk_to_pk(secret_key: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], BLST_ERROR> {
    let secret_key = SecretKey::from_bytes(secret_key)?;
    Ok(secret_key.sk_to_pk().to_bytes())
}

/// Sign a message with a private key.
fn sign(secret_key: &[u8], message: &[u8]) -> Result<[u8; SIGNATURE_LEN], BLST_ERROR> {
    let secret_key = SecretKey::from_bytes(secret_key)?;
    Ok(secret_key.sign(message, DST_SIG, &[]).to_bytes())
}

/// Produce a proof-of-possession: a signature over the public key under the PoP domain tag.
fn pop_prove(secret_key: &[u8]) -> Result<[u8; SIGNATURE_LEN], BLST_ERROR> {
    let secret_key = SecretKey::from_bytes(secret_key)?;
    let public_key = secret_key.sk_to_pk();
    Ok(secret_key
        .sign(&public_key.to_bytes(), DST_POP, &[])
        .to_bytes())
}

/// Verify a proof-of-possession for a public key. False on malformed input.
fn pop_verify(public_key: &[u8], pop: &[u8]) -> bool {
    let (Ok(public_key), Ok(signature)) = (
        PublicKey::from_bytes(public_key),
        Signature::from_bytes(pop),
    ) else {
        return false;
    };
    let result = signature.verify(
        true,
        &public_key.to_bytes(),
        DST_POP,
        &[],
        &public_key,
        true,
    );
    result == BLST_ERROR::BLST_SUCCESS
}

/// Verify a single signature. False on malformed input.
fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public_key), Ok(signature)) = (
        PublicKey::from_bytes(public_key),
        Signature::from_bytes(signature),
    ) else {
        return false;
    };
    let result = signature.verify(true, message, DST_SIG, &[], &public_key, true);
    result == BLST_ERROR::BLST_SUCCESS
}

/// Aggregate one or more signatures into a single signature. The members are aggregated without a
/// subgroup recheck: callers verify each member *before* aggregating (aggregation cannot localize an
/// invalid member, so one bad signature silently poisons the result).
fn aggregate(signatures: &[Vec<u8>]) -> Result<[u8; SIGNATURE_LEN], BLST_ERROR> {
    let mut parsed = Vec::with_capacity(signatures.len());
    for signature in signatures {
        parsed.push(Signature::from_bytes(signature)?);
    }
    let refs: Vec<&Signature> = parsed.iter().collect();
    let aggregate = AggregateSignature::aggregate(&refs, false)?;
    Ok(aggregate.to_signature().to_bytes())
}

/// Verify an aggregate signature where every signer signed the *same* message. False on an empty key
/// set or malformed input.
fn fast_aggregate_verify(
    public_keys: &[Vec<u8>],
    message: &[u8],
    aggregate_signature: &[u8],
) -> bool {
    if public_keys.is_empty() {
        return false;
    }
    let Ok(signature) = Signature::from_bytes(aggregate_signature) else {
        return false;
    };
    let mut parsed = Vec::with_capacity(public_keys.len());
    for public_key in public_keys {
        let Ok(public_key) = PublicKey::from_bytes(public_key) else {
            return false;
        };
        parsed.push(public_key);
    }
    let refs: Vec<&PublicKey> = parsed.iter().collect();
    let result = signature.fast_aggregate_verify(true, message, DST_SIG, &refs);
    result == BLST_ERROR::BLST_SUCCESS
}

/// Derive a BLS private key from input key material (>= 32 bytes of entropy).
#[pyfunction]
pub fn bls_keygen<'py>(py: Python<'py>, ikm: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let secret_key = keygen(ikm).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &secret_key))
}

/// Return the compressed public key for a private key.
#[pyfunction]
pub fn bls_sk_to_pk<'py>(py: Python<'py>, secret_key: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let public_key = sk_to_pk(secret_key).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &public_key))
}

/// Produce a proof-of-possession for a private key.
#[pyfunction]
pub fn bls_pop_prove<'py>(py: Python<'py>, secret_key: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let pop = pop_prove(secret_key).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &pop))
}

/// Verify a proof-of-possession for a public key. Returns False on malformed input.
#[pyfunction]
pub fn bls_pop_verify(public_key: &[u8], pop: &[u8]) -> bool {
    pop_verify(public_key, pop)
}

/// Sign a message with a private key.
#[pyfunction]
pub fn bls_sign<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = sign(secret_key, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

/// Verify a single signature. Returns False on malformed input.
#[pyfunction]
pub fn bls_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify(public_key, message, signature)
}

/// Aggregate a non-empty sequence of signatures into a single signature.
#[pyfunction]
pub fn bls_aggregate<'py>(
    py: Python<'py>,
    signatures: Vec<Vec<u8>>,
) -> PyResult<Bound<'py, PyBytes>> {
    if signatures.is_empty() {
        return Err(PyValueError::new_err(
            "cannot aggregate an empty sequence of signatures",
        ));
    }
    let aggregate = aggregate(&signatures).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &aggregate))
}

/// Verify an aggregate signature over a single shared message. Returns False on an empty key set or
/// malformed input.
#[pyfunction]
pub fn bls_fast_aggregate_verify(
    public_keys: Vec<Vec<u8>>,
    message: &[u8],
    aggregate_signature: &[u8],
) -> bool {
    fast_aggregate_verify(&public_keys, message, aggregate_signature)
}

/// Register the BLS functions on the extension module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(bls_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(bls_sk_to_pk, m)?)?;
    m.add_function(wrap_pyfunction!(bls_pop_prove, m)?)?;
    m.add_function(wrap_pyfunction!(bls_pop_verify, m)?)?;
    m.add_function(wrap_pyfunction!(bls_sign, m)?)?;
    m.add_function(wrap_pyfunction!(bls_verify, m)?)?;
    m.add_function(wrap_pyfunction!(bls_aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(bls_fast_aggregate_verify, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ikm(seed: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = 0xa5; // keep >= 32 bytes of non-trivial entropy
        bytes
    }

    #[test]
    fn test_sign_verify_round_trip() {
        let sk = keygen(&ikm(1)).unwrap();
        let pk = sk_to_pk(&sk).unwrap();
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);

        let signature = sign(&sk, b"a message").unwrap();
        assert_eq!(signature.len(), SIGNATURE_LEN);
        assert!(verify(&pk, b"a message", &signature));
        assert!(!verify(&pk, b"another message", &signature));
    }

    #[test]
    fn test_verify_rejects_malformed() {
        let sk = keygen(&ikm(2)).unwrap();
        let pk = sk_to_pk(&sk).unwrap();
        let signature = sign(&sk, b"msg").unwrap();
        assert!(!verify(&[0u8; 10], b"msg", &signature));
        assert!(!verify(&pk, b"msg", &[0u8; 10]));
    }

    #[test]
    fn test_proof_of_possession() {
        let sk = keygen(&ikm(3)).unwrap();
        let pk = sk_to_pk(&sk).unwrap();
        let pop = pop_prove(&sk).unwrap();
        assert!(pop_verify(&pk, &pop));

        let other_pop = pop_prove(&keygen(&ikm(4)).unwrap()).unwrap();
        assert!(!pop_verify(&pk, &other_pop));
        assert!(!pop_verify(&[0u8; 10], &[0u8; 10]));
    }

    #[test]
    fn test_fast_aggregate_verify_same_message() {
        let secret_keys: Vec<[u8; 32]> = (0..4).map(|i| keygen(&ikm(10 + i)).unwrap()).collect();
        let public_keys: Vec<Vec<u8>> = secret_keys
            .iter()
            .map(|sk| sk_to_pk(sk).unwrap().to_vec())
            .collect();
        let message = b"shared finality pin message";

        let signatures: Vec<Vec<u8>> = secret_keys
            .iter()
            .map(|sk| sign(sk, message).unwrap().to_vec())
            .collect();
        let aggregate = aggregate(&signatures).unwrap();

        assert!(fast_aggregate_verify(&public_keys, message, &aggregate));
        // A strict subset of the signers must not verify the full aggregate.
        assert!(!fast_aggregate_verify(
            &public_keys[..3],
            message,
            &aggregate
        ));
        // The aggregate must not verify against a different message.
        assert!(!fast_aggregate_verify(
            &public_keys,
            b"other message",
            &aggregate
        ));
        // An empty key set is rejected.
        assert!(!fast_aggregate_verify(&[], message, &aggregate));
    }
}
