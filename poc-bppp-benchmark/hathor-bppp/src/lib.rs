//! PyO3 bindings exposing bp-pp's u64 range proof to the Python benchmarks.
//!
//! Mirrors the function shapes used by `hathor.crypto.shielded.range_proof` so the
//! existing benchmark scripts can swap modules with minimal changes.

use std::ops::Deref;
use std::sync::OnceLock;

use bp_pp::range_proof;
use bp_pp::range_proof::u64_proof::{H_VEC_FULL_SZ, G_VEC_FULL_SZ, U64RangeProofProtocol};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use merlin::Transcript;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const TRANSCRIPT_LABEL: &[u8] = b"hathor-bppp-u64-range-proof";
const PROTOCOL_SEED: u64 = 0x6843_7430_5042_5050; // "HCt0PBPP" -- arbitrary fixed seed
const POINT_SIZE: usize = 33;
const SCALAR_SIZE: usize = 32;

fn protocol() -> &'static U64RangeProofProtocol {
    static PROTO: OnceLock<U64RangeProofProtocol> = OnceLock::new();
    PROTO.get_or_init(|| {
        // Deterministic NUMS-ish generators from a fixed seed.
        // Not security-meaningful: the benchmark only times prove/verify; it does not
        // assert binding/hiding properties of these generators.
        let mut rng = ChaCha20Rng::seed_from_u64(PROTOCOL_SEED);
        let g = ProjectivePoint::random(&mut rng);
        let g_vec = (0..G_VEC_FULL_SZ)
            .map(|_| ProjectivePoint::random(&mut rng))
            .collect::<Vec<_>>();
        let h_vec = (0..H_VEC_FULL_SZ)
            .map(|_| ProjectivePoint::random(&mut rng))
            .collect::<Vec<_>>();
        U64RangeProofProtocol { g, g_vec, h_vec }
    })
}

fn scalar_from_blinding(blinding: &[u8]) -> PyResult<Scalar> {
    if blinding.len() != 32 {
        return Err(PyValueError::new_err("blinding must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(blinding);
    // Try direct decode; fall back to reducing the raw bytes through
    // `Scalar::from_bytes_reduced` semantics by hashing if the canonical decode fails.
    let ct = Scalar::from_repr(arr.into());
    if bool::from(ct.is_some()) {
        Ok(ct.unwrap())
    } else {
        // Highly unlikely path (probability ~2^-128). Reduce by truncation: clear
        // the top byte and try again so the benchmark never blows up on a random
        // 32-byte sequence that happens to exceed the group order.
        arr[0] &= 0x7f;
        let ct2 = Scalar::from_repr(arr.into());
        if bool::from(ct2.is_some()) {
            Ok(ct2.unwrap())
        } else {
            Err(PyValueError::new_err("blinding bytes do not decode to a scalar"))
        }
    }
}

fn point_to_bytes(p: &ProjectivePoint) -> [u8; POINT_SIZE] {
    let aff = p.to_affine();
    let enc = aff.to_encoded_point(true);
    let mut out = [0u8; POINT_SIZE];
    let bytes = enc.as_bytes();
    // SEC1 compressed encoding of an affine point is 33 bytes.
    // The identity element on k256 encodes to a single 0x00 byte; pad in that case so
    // wire-size accounting stays uniform across all proof slots.
    if bytes.len() == POINT_SIZE {
        out.copy_from_slice(bytes);
    } else {
        out[..bytes.len()].copy_from_slice(bytes);
    }
    out
}

fn point_from_bytes(bytes: &[u8]) -> PyResult<ProjectivePoint> {
    if bytes.len() != POINT_SIZE {
        return Err(PyValueError::new_err("point must be 33 bytes"));
    }
    // Identity-padded slot (see point_to_bytes): treat leading 0x00 + zeros as identity.
    if bytes[0] == 0 && bytes[1..].iter().all(|&b| b == 0) {
        return Ok(ProjectivePoint::IDENTITY);
    }
    let enc = EncodedPoint::from_bytes(bytes)
        .map_err(|e| PyValueError::new_err(format!("invalid SEC1 point: {e}")))?;
    let aff_ct = AffinePoint::from_encoded_point(&enc);
    if bool::from(aff_ct.is_some()) {
        Ok(ProjectivePoint::from(aff_ct.unwrap()))
    } else {
        Err(PyValueError::new_err("point not on curve"))
    }
}

fn scalar_to_bytes(s: &Scalar) -> [u8; SCALAR_SIZE] {
    s.to_bytes().into()
}

fn scalar_from_bytes(bytes: &[u8]) -> PyResult<Scalar> {
    if bytes.len() != SCALAR_SIZE {
        return Err(PyValueError::new_err("scalar must be 32 bytes"));
    }
    let mut arr = [0u8; SCALAR_SIZE];
    arr.copy_from_slice(bytes);
    let ct = Scalar::from_repr(arr.into());
    if bool::from(ct.is_some()) {
        Ok(ct.unwrap())
    } else {
        Err(PyValueError::new_err("scalar decode failed"))
    }
}

// ---------------------------------------------------------------------------
// Compact proof serialization. Fixed-size points (33B) and scalars (32B), with
// 4-byte big-endian length prefixes for the variable-length vectors. This is
// the size used for the bandwidth/memory benchmark.
// ---------------------------------------------------------------------------

fn serialize_proof(proof: &range_proof::reciprocal::Proof) -> Vec<u8> {
    let mut out = Vec::with_capacity(4096);
    let cp = &proof.circuit_proof;
    out.extend_from_slice(&point_to_bytes(&proof.r));
    out.extend_from_slice(&point_to_bytes(&cp.c_l));
    out.extend_from_slice(&point_to_bytes(&cp.c_r));
    out.extend_from_slice(&point_to_bytes(&cp.c_o));
    out.extend_from_slice(&point_to_bytes(&cp.c_s));
    out.extend_from_slice(&(cp.r.len() as u32).to_be_bytes());
    for p in &cp.r {
        out.extend_from_slice(&point_to_bytes(p));
    }
    out.extend_from_slice(&(cp.x.len() as u32).to_be_bytes());
    for p in &cp.x {
        out.extend_from_slice(&point_to_bytes(p));
    }
    out.extend_from_slice(&(cp.l.len() as u32).to_be_bytes());
    for s in &cp.l {
        out.extend_from_slice(&scalar_to_bytes(s));
    }
    out.extend_from_slice(&(cp.n.len() as u32).to_be_bytes());
    for s in &cp.n {
        out.extend_from_slice(&scalar_to_bytes(s));
    }
    out
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> PyResult<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(PyValueError::new_err("proof bytes truncated"));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn take_u32(&mut self) -> PyResult<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
}

fn deserialize_proof(bytes: &[u8]) -> PyResult<range_proof::reciprocal::Proof> {
    let mut c = Cursor::new(bytes);
    let r = point_from_bytes(c.take(POINT_SIZE)?)?;
    let c_l = point_from_bytes(c.take(POINT_SIZE)?)?;
    let c_r = point_from_bytes(c.take(POINT_SIZE)?)?;
    let c_o = point_from_bytes(c.take(POINT_SIZE)?)?;
    let c_s = point_from_bytes(c.take(POINT_SIZE)?)?;
    let n_r = c.take_u32()? as usize;
    let mut r_vec = Vec::with_capacity(n_r);
    for _ in 0..n_r {
        r_vec.push(point_from_bytes(c.take(POINT_SIZE)?)?);
    }
    let n_x = c.take_u32()? as usize;
    let mut x_vec = Vec::with_capacity(n_x);
    for _ in 0..n_x {
        x_vec.push(point_from_bytes(c.take(POINT_SIZE)?)?);
    }
    let n_l = c.take_u32()? as usize;
    let mut l_vec = Vec::with_capacity(n_l);
    for _ in 0..n_l {
        l_vec.push(scalar_from_bytes(c.take(SCALAR_SIZE)?)?);
    }
    let n_n = c.take_u32()? as usize;
    let mut n_vec = Vec::with_capacity(n_n);
    for _ in 0..n_n {
        n_vec.push(scalar_from_bytes(c.take(SCALAR_SIZE)?)?);
    }
    Ok(range_proof::reciprocal::Proof {
        circuit_proof: bp_pp::circuit::Proof {
            c_l,
            c_r,
            c_o,
            c_s,
            r: r_vec,
            x: x_vec,
            l: l_vec,
            n: n_vec,
        },
        r,
    })
}

// ---------------------------------------------------------------------------
// PyO3 surface
// ---------------------------------------------------------------------------

/// Compute the bppp value commitment `amount * g + blinding * h_vec[0]`.
///
/// Extra arguments (generator) are accepted for signature parity with the
/// secp256k1-zkp Pedersen commitment but are ignored — bppp uses its own base
/// points.
#[pyfunction]
#[pyo3(signature = (amount, blinding, _generator=None))]
fn create_commitment(
    py: Python<'_>,
    amount: u64,
    blinding: &[u8],
    _generator: Option<&[u8]>,
) -> PyResult<PyObject> {
    let s = scalar_from_blinding(blinding)?;
    let proto = protocol();
    let c = proto.commit_value(amount, &s);
    Ok(PyBytes::new_bound(py, &point_to_bytes(&c)).into())
}

/// Build a u64 bppp range proof for `amount` with blinding `blinding`.
///
/// Returns the compact serialized proof. The auxiliary `commitment`, `generator`,
/// `message`, and `nonce` parameters are accepted for compatibility with the
/// secp256k1-zkp range-proof API but are not consumed by bppp.
#[pyfunction]
#[pyo3(signature = (amount, blinding, _commitment=None, _generator=None, _message=None, _nonce=None))]
fn create_range_proof(
    py: Python<'_>,
    amount: u64,
    blinding: &[u8],
    _commitment: Option<&[u8]>,
    _generator: Option<&[u8]>,
    _message: Option<&[u8]>,
    _nonce: Option<&[u8]>,
) -> PyResult<PyObject> {
    let s = scalar_from_blinding(blinding)?;
    let proto = protocol();
    let mut t = Transcript::new(TRANSCRIPT_LABEL);
    let mut rng = rand::thread_rng();
    let proof = proto.prove(amount, &s, &mut t, &mut rng);
    let bytes = serialize_proof(&proof);
    Ok(PyBytes::new_bound(py, &bytes).into())
}

/// Verify a bppp range proof against the given commitment.
///
/// `generator` is accepted for signature parity with the secp256k1-zkp range
/// proof verify call but is ignored.
#[pyfunction]
#[pyo3(signature = (proof, commitment, _generator=None))]
fn verify_range_proof(
    proof: &[u8],
    commitment: &[u8],
    _generator: Option<&[u8]>,
) -> PyResult<bool> {
    let p = deserialize_proof(proof)?;
    let c = point_from_bytes(commitment)?;
    let proto = protocol();
    let mut t = Transcript::new(TRANSCRIPT_LABEL);
    Ok(proto.verify(&c, p, &mut t))
}

/// One-shot helper: returns (commitment_bytes, proof_bytes) so callers can prove and
/// keep the commitment in one trip across the FFI boundary.
#[pyfunction]
fn commit_and_prove(
    py: Python<'_>,
    amount: u64,
    blinding: &[u8],
) -> PyResult<(PyObject, PyObject)> {
    let s = scalar_from_blinding(blinding)?;
    let proto = protocol();
    let c = proto.commit_value(amount, &s);
    let mut t = Transcript::new(TRANSCRIPT_LABEL);
    let mut rng = rand::thread_rng();
    let proof = proto.prove(amount, &s, &mut t, &mut rng);
    let proof_bytes = serialize_proof(&proof);
    let comm_bytes = point_to_bytes(&c);
    Ok((
        PyBytes::new_bound(py, &comm_bytes).into(),
        PyBytes::new_bound(py, &proof_bytes).into(),
    ))
}

/// Diagnostic: produce a proof for amount=2^60 and return its byte length.
#[pyfunction]
fn proof_size_bytes() -> PyResult<usize> {
    let proto = protocol();
    let mut t = Transcript::new(TRANSCRIPT_LABEL);
    let mut rng = rand::thread_rng();
    // Use a fixed non-trivial scalar so the test is reproducible.
    let s = Scalar::ONE;
    let proof = proto.prove(1u64 << 60, &s, &mut t, &mut rng);
    Ok(serialize_proof(&proof).deref().len())
}

#[pymodule]
fn hathor_bppp(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(create_range_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_range_proof, m)?)?;
    m.add_function(wrap_pyfunction!(commit_and_prove, m)?)?;
    m.add_function(wrap_pyfunction!(proof_size_bytes, m)?)?;
    Ok(())
}
