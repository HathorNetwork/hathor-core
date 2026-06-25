// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! SignedAmount Python wrapper.

use crate::unsigned_amount::PyUnsignedAmount;
use htr_lib::SignedAmount;
use num_bigint::BigInt;
use pyo3::exceptions::{PyAssertionError, PyTypeError};
use pyo3::prelude::*;

/// Python-facing wrapper around [`SignedAmount`].
///
/// `frozen` + `immutable_type` make both instances and the class itself unmodifiable from
/// Python, so signed amounts have value semantics like `int`.
#[pyclass(name = "SignedAmount", frozen, immutable_type)]
pub struct PySignedAmount(SignedAmount);

impl PySignedAmount {
    pub(crate) fn new(amount: SignedAmount) -> Self {
        Self(amount)
    }
}

#[pymethods]
impl PySignedAmount {
    #[new]
    #[pyo3(signature = (amount = BigInt::ZERO))]
    fn py_new(amount: BigInt) -> Self {
        Self(SignedAmount::new(amount))
    }

    fn raw(&self) -> &BigInt {
        self.0.raw()
    }

    /// Identity. Mirrors [`PyUnsignedAmount::to_signed`] so Python callers can convert a
    /// value of unknown type (unsigned or signed) to a signed amount through a uniform method.
    fn to_signed(slf: PyRef<'_, PySignedAmount>) -> PyRef<'_, PySignedAmount> {
        slf
    }

    fn to_unsigned(&self) -> PyResult<PyUnsignedAmount> {
        self.0
            .to_unsigned()
            .map(PyUnsignedAmount::new)
            .ok_or_else(|| {
                PyAssertionError::new_err(format!(
                    "cannot convert negative SignedAmount to UnsignedAmount ({:?})",
                    self.0,
                ))
            })
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }

    fn __bool__(&self) -> bool {
        self.0.as_bool()
    }

    fn __add__(&self, other: &Self) -> Self {
        Self(&self.0 + &other.0)
    }

    fn __sub__(&self, other: &Self) -> Self {
        Self(&self.0 - &other.0)
    }

    fn __neg__(&self) -> Self {
        Self(-&self.0)
    }

    fn __pos__(slf: PyRef<'_, PySignedAmount>) -> PyRef<'_, PySignedAmount> {
        slf
    }

    fn __richcmp__(&self, other: &Bound<'_, PyAny>, op: pyo3::basic::CompareOp) -> PyResult<bool> {
        // Accept any object and raise `TypeError` on a non-`SignedAmount` operand so that
        // `==`/`!=` against a foreign type fail loudly. PyO3 returns `NotImplemented` automatically
        // which would let Python fall back to object identity and silently yield a wrong boolean.
        if let Ok(other) = other.cast_exact::<PySignedAmount>() {
            Ok(op.matches(self.0.cmp(&other.get().0)))
        } else {
            let type_name = other
                .get_type()
                .name()
                .map(|n| n.to_string())
                .unwrap_or_else(|_| "<unknown type>".to_owned());
            Err(PyTypeError::new_err(format!(
                "comparison not supported between instances of 'SignedAmount' and '{type_name}'",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use htr_lib::UnsignedAmount;
    use num_bigint::BigUint;

    fn ibig(n: i64) -> BigInt {
        BigInt::from(n)
    }

    fn signed(n: i64) -> SignedAmount {
        SignedAmount::new(ibig(n))
    }

    #[test]
    fn py_to_unsigned_negative_raises_assertion_error() {
        Python::initialize();
        Python::attach(|py| {
            let pb = PySignedAmount::new(signed(-5));
            let Err(err) = pb.to_unsigned() else {
                panic!("expected AssertionError on negative signed amount");
            };
            assert!(err.is_instance_of::<PyAssertionError>(py));
            assert_eq!(
                err.value(py).to_string(),
                "cannot convert negative SignedAmount to UnsignedAmount (SignedAmount(-5))"
            );
        });
    }

    // Pins the value carried over by the conversion, not just `.is_ok()` — a refactor
    // that silently returned `UnsignedAmount::ZERO` for any non-negative signed amount would
    // pass a structure-only check. Asserting through `repr()` pins both variant
    // (`V2`) and the contained `BigUint` in a single exact string.
    #[test]
    fn py_to_unsigned_non_negative_pins_value() {
        Python::initialize();
        Python::attach(|py| {
            for (input, expected_repr) in
                [(5_i64, "V2 { normalized: 5 }"), (0, "V2 { normalized: 0 }")]
            {
                let result = Bound::new(py, PySignedAmount::new(signed(input)))
                    .unwrap()
                    .call_method0("to_unsigned")
                    .unwrap();
                let repr: String = result.repr().unwrap().extract().unwrap();
                assert_eq!(repr, expected_repr);
            }
        });
    }

    // Goes through Python's `repr()` so the `tp_repr` slot is exercised: `__repr__` exposes
    // the inner tuple struct's Debug form, signed `BigInt` included.
    #[test]
    fn py_repr_pins_debug_form() {
        Python::initialize();
        Python::attach(|py| {
            for (input, expected) in [
                (0_i64, "SignedAmount(0)"),
                (5, "SignedAmount(5)"),
                (-5, "SignedAmount(-5)"),
            ] {
                let bound = Bound::new(py, PySignedAmount::new(signed(input))).unwrap();
                let repr: String = bound.as_any().repr().unwrap().extract().unwrap();
                assert_eq!(repr, expected);
            }
        });
    }

    // Goes through Python's `str()` so the `tp_str` slot is exercised: `__str__` renders the
    // V2-normalized value at eighteen fractional digits, always with the point and at least one
    // fractional digit, prefixing `-` for negatives and rendering zero as `0.0`.
    #[test]
    fn py_str_renders_trimmed_decimal_with_sign() {
        UnsignedAmount::set_decimal_places(2, 18);
        Python::initialize();
        Python::attach(|py| {
            for (input, expected) in [
                (0_i64, "0.0"),
                (5, "0.000000000000000005"),
                (-5, "-0.000000000000000005"),
                (1_500_000_000_000_000_000, "1.5"),
                (-1_500_000_000_000_000_000, "-1.5"),
            ] {
                let bound = Bound::new(py, PySignedAmount::new(signed(input))).unwrap();
                let rendered: String = bound.as_any().str().unwrap().extract().unwrap();
                assert_eq!(rendered, expected);
            }
        });
    }

    #[test]
    fn py_to_signed_returns_same_python_object() {
        Python::initialize();
        Python::attach(|py| {
            let pb = Bound::new(py, PySignedAmount::new(signed(5))).unwrap();
            let returned = pb.call_method0("to_signed").unwrap();
            assert!(returned.is(&pb));
        });
    }

    #[test]
    fn py_pos_returns_same_python_object() {
        Python::initialize();
        Python::attach(|py| {
            let pb = Bound::new(py, PySignedAmount::new(signed(5))).unwrap();
            let returned = pb.call_method0("__pos__").unwrap();
            assert!(returned.is(&pb));
        });
    }

    // Goes through Python attribute lookup so the `#[pymethods]` wiring is exercised:
    // a swap between `__add__`, `__sub__`, and `__neg__` in the source would still
    // compile, and the inner `Add`/`Sub`/`Neg` tests above would still pass — only
    // these tests would catch it.
    #[test]
    fn py_add_forwards_through_python_dispatch() {
        Python::initialize();
        Python::attach(|py| {
            let a = Bound::new(py, PySignedAmount::new(signed(2))).unwrap();
            let b = Bound::new(py, PySignedAmount::new(signed(3))).unwrap();
            let result = a.call_method1("__add__", (b,)).unwrap();
            let result: PyRef<'_, PySignedAmount> = result.extract().unwrap();
            assert_eq!(result.raw(), &ibig(5));
        });
    }

    #[test]
    fn py_sub_forwards_through_python_dispatch() {
        Python::initialize();
        Python::attach(|py| {
            let a = Bound::new(py, PySignedAmount::new(signed(5))).unwrap();
            let b = Bound::new(py, PySignedAmount::new(signed(3))).unwrap();
            let result = a.call_method1("__sub__", (b,)).unwrap();
            let result: PyRef<'_, PySignedAmount> = result.extract().unwrap();
            assert_eq!(result.raw(), &ibig(2));
        });
    }

    #[test]
    fn py_neg_forwards_through_python_dispatch() {
        Python::initialize();
        Python::attach(|py| {
            let pb = Bound::new(py, PySignedAmount::new(signed(5))).unwrap();
            let result = pb.call_method0("__neg__").unwrap();
            let result: PyRef<'_, PySignedAmount> = result.extract().unwrap();
            assert_eq!(result.raw(), &ibig(-5));
        });
    }

    #[test]
    fn py_same_type_comparisons_through_operator_dispatch() {
        Python::initialize();
        Python::attach(|py| {
            let a = Bound::new(py, PySignedAmount::new(signed(5))).unwrap();
            let b = Bound::new(py, PySignedAmount::new(signed(5))).unwrap();
            let smaller = Bound::new(py, PySignedAmount::new(signed(-1))).unwrap();
            let a_any = a.as_any();
            let b_any = b.as_any();
            let smaller_any = smaller.as_any();

            assert!(a_any.eq(b_any).unwrap());
            assert!(!a_any.ne(b_any).unwrap());
            assert!(a_any.le(b_any).unwrap());
            assert!(a_any.ge(b_any).unwrap());
            assert!(a_any.gt(smaller_any).unwrap());
            assert!(smaller_any.lt(a_any).unwrap());
        });
    }

    // Exercises the full `tp_richcompare` dispatch path used by Python's `==` / `<` / etc.
    // The invariant: a cross-type comparison surfaces `TypeError` through the type slot,
    // so `signed == 5` raises end-to-end and Python never falls back to identity equality.
    #[test]
    fn py_comparison_with_int_raises_type_error_via_python_operators() {
        Python::initialize();
        Python::attach(|py| {
            let pb = Bound::new(py, PySignedAmount::new(signed(5))).unwrap();
            let other = 5i32.into_pyobject(py).unwrap();
            let pb_any = pb.as_any();
            let other_any = other.as_any();
            let expected_msg =
                "comparison not supported between instances of 'SignedAmount' and 'int'";

            for (op, result) in [
                ("==", pb_any.eq(other_any)),
                ("!=", pb_any.ne(other_any)),
                ("<", pb_any.lt(other_any)),
                ("<=", pb_any.le(other_any)),
                (">", pb_any.gt(other_any)),
                (">=", pb_any.ge(other_any)),
            ] {
                let err = result
                    .err()
                    .unwrap_or_else(|| panic!("expected TypeError from `{op}`"));
                assert!(err.is_instance_of::<PyTypeError>(py), "operator `{op}`");
                assert_eq!(err.value(py).to_string(), expected_msg, "operator `{op}`");
            }
        });
    }

    // The sibling PyClass is the realistic confusion case in this codebase. Pinning the
    // type-name in the error confirms `cast_exact::<PySignedAmount>` rejects `PyUnsignedAmount`
    // and surfaces it as the foreign type, not the catch-all `"unknown type"` fallback.
    #[test]
    fn py_comparison_with_unsigned_amount_raises_type_error() {
        Python::initialize();
        Python::attach(|py| {
            let pb = Bound::new(py, PySignedAmount::new(signed(5))).unwrap();
            let amount = Bound::new(
                py,
                PyUnsignedAmount::new(UnsignedAmount::from_v2(BigUint::from(5u32))),
            )
            .unwrap();
            let err = pb
                .as_any()
                .eq(amount.as_any())
                .expect_err("expected TypeError when comparing SignedAmount with UnsignedAmount");
            assert!(err.is_instance_of::<PyTypeError>(py));
            assert_eq!(
                err.value(py).to_string(),
                "comparison not supported between instances of 'SignedAmount' and 'UnsignedAmount'"
            );
        });
    }
}
