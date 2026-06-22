//! Python extension module exposing Hathor's Rust implementations via PyO3.

mod signed_amount;
mod unsigned_amount;

use crate::signed_amount::PySignedAmount;
use crate::unsigned_amount::PyUnsignedAmount;
use pyo3::prelude::*;

/// Formats the sum of two numbers as string.
#[pyfunction]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

/// A Python module implemented in Rust.
#[pymodule]
fn htr_lib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    m.add_class::<PyUnsignedAmount>()?;
    m.add_class::<PySignedAmount>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyModule;

    #[test]
    fn test_sum_as_string() {
        assert_eq!(sum_as_string(2, 3).unwrap(), "5");
    }

    // Drives sum_as_string through PyO3 dispatch so the #[pymodule] init runs under coverage —
    // a direct Rust call leaves the registration block unexecuted.
    #[test]
    fn test_pymodule_registration() {
        Python::initialize();
        Python::attach(|py| {
            let module = PyModule::new(py, "htr_lib").unwrap();
            htr_lib(&module).unwrap();
            let result: String = module
                .getattr("sum_as_string")
                .unwrap()
                .call1((2, 3))
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(result, "5");
        });
    }
}
