//! TokenBalance Python wrapper.

use crate::token_amount::PyTokenAmount;
use htr_lib::TokenBalance;
use num_bigint::BigInt;
use pyo3::exceptions::{PyAssertionError, PyTypeError};
use pyo3::prelude::*;

/// Python-facing wrapper around [`TokenBalance`].
///
/// `frozen` + `immutable_type` make both instances and the class itself unmodifiable from
/// Python, so balances have value semantics like `int`.
#[pyclass(name = "TokenBalance", frozen, immutable_type)]
pub struct PyTokenBalance(TokenBalance);

impl PyTokenBalance {
    pub(crate) fn new(balance: TokenBalance) -> Self {
        Self(balance)
    }
}

#[pymethods]
impl PyTokenBalance {
    #[new]
    #[pyo3(signature = (balance = BigInt::ZERO))]
    fn py_new(balance: BigInt) -> Self {
        Self(TokenBalance::new(balance))
    }

    fn raw(&self) -> &BigInt {
        self.0.raw()
    }

    /// Identity. Mirrors [`PyTokenAmount::to_balance`] so Python callers can convert a
    /// value of unknown type (amount or balance) to a balance through a uniform method.
    fn to_balance(slf: PyRef<'_, PyTokenBalance>) -> PyRef<'_, PyTokenBalance> {
        slf
    }

    fn to_amount(&self) -> PyResult<PyTokenAmount> {
        self.0.to_amount().map(PyTokenAmount::new).ok_or_else(|| {
            PyAssertionError::new_err(format!(
                "cannot convert negative TokenBalance to TokenAmount ({:?})",
                self.0,
            ))
        })
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
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

    fn __pos__(slf: PyRef<'_, PyTokenBalance>) -> PyRef<'_, PyTokenBalance> {
        slf
    }

    fn __richcmp__(&self, other: &Bound<'_, PyAny>, op: pyo3::basic::CompareOp) -> PyResult<bool> {
        // Accept any object and raise `TypeError` on a non-`TokenBalance` operand so that
        // `==`/`!=` against a foreign type fail loudly. PyO3 returns `NotImplemented` automatically
        // which would let Python fall back to object identity and silently yield a wrong boolean.
        if let Ok(other) = other.cast_exact::<PyTokenBalance>() {
            Ok(op.matches(self.0.cmp(&other.get().0)))
        } else {
            let type_name = other
                .get_type()
                .name()
                .map(|n| n.to_string())
                .unwrap_or_else(|_| "<unknown type>".to_owned());
            Err(PyTypeError::new_err(format!(
                "comparison not supported between instances of 'TokenBalance' and '{type_name}'",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use htr_lib::TokenAmount;
    use num_bigint::BigUint;

    fn ibig(n: i64) -> BigInt {
        BigInt::from(n)
    }

    fn balance(n: i64) -> TokenBalance {
        TokenBalance::new(ibig(n))
    }

    #[test]
    fn py_to_amount_negative_raises_assertion_error() {
        Python::initialize();
        Python::attach(|py| {
            let pb = PyTokenBalance::new(balance(-5));
            let Err(err) = pb.to_amount() else {
                panic!("expected AssertionError on negative balance");
            };
            assert!(err.is_instance_of::<PyAssertionError>(py));
            assert_eq!(
                err.value(py).to_string(),
                "cannot convert negative TokenBalance to TokenAmount (TokenBalance(-5))"
            );
        });
    }

    // Pins the value carried over by the conversion, not just `.is_ok()` — a refactor
    // that silently returned `TokenAmount::ZERO` for any non-negative balance would
    // pass a structure-only check. Asserting through `repr()` pins both variant
    // (`V2`) and the contained `BigUint` in a single exact string.
    #[test]
    fn py_to_amount_non_negative_pins_value() {
        Python::initialize();
        Python::attach(|py| {
            for (input, expected_repr) in
                [(5_i64, "V2 { normalized: 5 }"), (0, "V2 { normalized: 0 }")]
            {
                let result = Bound::new(py, PyTokenBalance::new(balance(input)))
                    .unwrap()
                    .call_method0("to_amount")
                    .unwrap();
                let repr: String = result.repr().unwrap().extract().unwrap();
                assert_eq!(repr, expected_repr);
            }
        });
    }

    #[test]
    fn py_to_balance_returns_same_python_object() {
        Python::initialize();
        Python::attach(|py| {
            let pb = Bound::new(py, PyTokenBalance::new(balance(5))).unwrap();
            let returned = pb.call_method0("to_balance").unwrap();
            assert!(returned.is(&pb));
        });
    }

    #[test]
    fn py_pos_returns_same_python_object() {
        Python::initialize();
        Python::attach(|py| {
            let pb = Bound::new(py, PyTokenBalance::new(balance(5))).unwrap();
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
            let a = Bound::new(py, PyTokenBalance::new(balance(2))).unwrap();
            let b = Bound::new(py, PyTokenBalance::new(balance(3))).unwrap();
            let result = a.call_method1("__add__", (b,)).unwrap();
            let result: PyRef<'_, PyTokenBalance> = result.extract().unwrap();
            assert_eq!(result.raw(), &ibig(5));
        });
    }

    #[test]
    fn py_sub_forwards_through_python_dispatch() {
        Python::initialize();
        Python::attach(|py| {
            let a = Bound::new(py, PyTokenBalance::new(balance(5))).unwrap();
            let b = Bound::new(py, PyTokenBalance::new(balance(3))).unwrap();
            let result = a.call_method1("__sub__", (b,)).unwrap();
            let result: PyRef<'_, PyTokenBalance> = result.extract().unwrap();
            assert_eq!(result.raw(), &ibig(2));
        });
    }

    #[test]
    fn py_neg_forwards_through_python_dispatch() {
        Python::initialize();
        Python::attach(|py| {
            let pb = Bound::new(py, PyTokenBalance::new(balance(5))).unwrap();
            let result = pb.call_method0("__neg__").unwrap();
            let result: PyRef<'_, PyTokenBalance> = result.extract().unwrap();
            assert_eq!(result.raw(), &ibig(-5));
        });
    }

    #[test]
    fn py_same_type_comparisons_through_operator_dispatch() {
        Python::initialize();
        Python::attach(|py| {
            let a = Bound::new(py, PyTokenBalance::new(balance(5))).unwrap();
            let b = Bound::new(py, PyTokenBalance::new(balance(5))).unwrap();
            let smaller = Bound::new(py, PyTokenBalance::new(balance(-1))).unwrap();
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
    // so `balance == 5` raises end-to-end and Python never falls back to identity equality.
    #[test]
    fn py_comparison_with_int_raises_type_error_via_python_operators() {
        Python::initialize();
        Python::attach(|py| {
            let pb = Bound::new(py, PyTokenBalance::new(balance(5))).unwrap();
            let other = 5i32.into_pyobject(py).unwrap();
            let pb_any = pb.as_any();
            let other_any = other.as_any();
            let expected_msg =
                "comparison not supported between instances of 'TokenBalance' and 'int'";

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
    // type-name in the error confirms `cast_exact::<PyTokenBalance>` rejects `PyTokenAmount`
    // and surfaces it as the foreign type, not the catch-all `"unknown type"` fallback.
    #[test]
    fn py_comparison_with_token_amount_raises_type_error() {
        Python::initialize();
        Python::attach(|py| {
            let pb = Bound::new(py, PyTokenBalance::new(balance(5))).unwrap();
            let amount = Bound::new(
                py,
                PyTokenAmount::new(TokenAmount::from_v2(BigUint::from(5u32))),
            )
            .unwrap();
            let err = pb
                .as_any()
                .eq(amount.as_any())
                .expect_err("expected TypeError when comparing TokenBalance with TokenAmount");
            assert!(err.is_instance_of::<PyTypeError>(py));
            assert_eq!(
                err.value(py).to_string(),
                "comparison not supported between instances of 'TokenBalance' and 'TokenAmount'"
            );
        });
    }
}
