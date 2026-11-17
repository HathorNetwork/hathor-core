// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! Python extension module exposing `htr-core`'s p2p wire codecs via PyO3.
//!
//! `htr-core` is the experimental Rust port; this crate is the only PyO3 boundary that depends
//! on it, keeping the experimental code out of the non-experimental binding crates. The functions
//! here let Python tests cross-check the Rust codecs against the reference implementation.

mod codec;
mod protocol_peer;

use crate::protocol_peer::ProtocolPeer;
use pyo3::prelude::*;

/// A Python module implemented in Rust.
#[pymodule]
fn htr_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    crate::codec::register(m)?;
    m.add_class::<ProtocolPeer>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyModule;

    // Drives the module init through PyO3 dispatch so the #[pymodule] registration runs under
    // coverage and we catch any registration breakage without the Python toolchain.
    #[test]
    fn test_pymodule_registration() {
        Python::initialize();
        Python::attach(|py| {
            let module = PyModule::new(py, "htr_core").unwrap();
            htr_core(&module).unwrap();
            assert!(module.getattr("vertex_decode_encode").is_ok());
            assert!(module.getattr("message_reencode").is_ok());
            assert!(module.getattr("ProtocolPeer").is_ok());
        });
    }
}
