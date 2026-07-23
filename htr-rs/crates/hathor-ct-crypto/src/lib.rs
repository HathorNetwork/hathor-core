// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! Python extension module exposing Hathor's confidential-transactions crypto to `hathor-core` via PyO3.
//!
//! This crate is intentionally empty for now: the Python type surface lives in
//! `hathor_ct_crypto.pyi`, and the real implementations land in a later PR.
//! Until then the compiled module exposes no functions, so any real access
//! fails at call time (mirroring the previous behaviour where the native
//! library was simply absent).

use pyo3::prelude::*;

// Prohibit compilation for non-64-bit targets to ensure consistent use of `usize`.
#[cfg(not(target_pointer_width = "64"))]
compile_error!("compilation is only allowed for 64-bit targets");

/// A Python module implemented in Rust.
#[pymodule]
fn hathor_ct_crypto(_m: &Bound<'_, PyModule>) -> PyResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyModule;

    // Drives the #[pymodule] init through PyO3 so the registration block runs under coverage.
    #[test]
    fn test_pymodule_registration() {
        Python::initialize();
        Python::attach(|py| {
            let module = PyModule::new(py, "hathor_ct_crypto").unwrap();
            hathor_ct_crypto(&module).unwrap();
        });
    }
}
