// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! Thin PyO3 wrappers over `htr-core`'s vertex and protocol-message codecs.
//!
//! These exist so Python tests can feed bytes and wire lines produced by the Python reference
//! implementation through the Rust codecs and assert byte-for-byte / parse-for-parse parity. The
//! wrappers stay deliberately dumb: bytes in, bytes out, strings in, strings out — all the
//! comparison logic lives in the Python test suite.

use htr_core::protocol::message::{
    AnyStateMessage, HelloStateMessage, PeerIdStateMessage, ReadyStateMessage,
};
use htr_core::vertex::{decode_any_vertex_data, encode_any_vertex_data};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Decode a serialized vertex with the Rust codec and re-encode it, returning the round-tripped
/// bytes.
///
/// Equality with the input proves the Rust codec reads and writes the Python reference's wire
/// format faithfully. Raises `ValueError` on malformed input.
#[pyfunction]
fn vertex_decode_encode<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let vertex = decode_any_vertex_data(data)
        .map_err(|e| PyValueError::new_err(format!("vertex decode failed: {e}")))?;
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    encode_any_vertex_data(&mut out, &vertex)
        .map_err(|e| PyValueError::new_err(format!("vertex encode failed: {e}")))?;
    Ok(PyBytes::new(py, &out))
}

/// Parse a single wire line in the given protocol state and re-render it via the Rust codec.
///
/// `state` selects which messages are accepted: `"hello"`, `"peer-id"`, `"ready"`, or `"any"`
/// (accepts every known message regardless of state). A line that is malformed or not valid in the
/// requested state raises `ValueError` — this is what lets out-of-state and negative tests assert
/// rejection.
#[pyfunction]
fn message_reencode(state: &str, line: &str) -> PyResult<String> {
    let rendered = match state {
        "hello" => line.parse::<HelloStateMessage>().map(|m| m.to_string()),
        "peer-id" => line.parse::<PeerIdStateMessage>().map(|m| m.to_string()),
        "ready" => line.parse::<ReadyStateMessage>().map(|m| m.to_string()),
        "any" => line.parse::<AnyStateMessage>().map(|m| m.to_string()),
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown protocol state: {other}"
            )));
        }
    };
    rendered.map_err(|e| PyValueError::new_err(format!("message parse failed: {e}")))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(vertex_decode_encode, m)?)?;
    m.add_function(wrap_pyfunction!(message_reencode, m)?)?;
    Ok(())
}
