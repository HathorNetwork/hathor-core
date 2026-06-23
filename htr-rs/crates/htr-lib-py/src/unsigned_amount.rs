//! UnsignedAmount Python wrapper.

use crate::signed_amount::PySignedAmount;
use htr_lib::{TokenAmountVersion, UnsignedAmount};
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use pyo3::exceptions::{PyAssertionError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyInt;

/// Python-facing wrapper around [`UnsignedAmount`].
///
/// `frozen` + `immutable_type` make both instances and the class itself unmodifiable from
/// Python, so amounts have value semantics like `int`.
#[pyclass(name = "UnsignedAmount", frozen, immutable_type)]
pub struct PyUnsignedAmount(UnsignedAmount);

impl PyUnsignedAmount {
    pub(crate) fn new(amount: UnsignedAmount) -> Self {
        Self(amount)
    }
}

#[pymethods]
impl PyUnsignedAmount {
    #[staticmethod]
    #[pyo3(signature = (*, v1_decimal_places, v2_decimal_places))]
    fn set_decimal_places(v1_decimal_places: u32, v2_decimal_places: u32) {
        UnsignedAmount::set_decimal_places(v1_decimal_places, v2_decimal_places)
    }

    #[staticmethod]
    fn get_normalization_factor() -> &'static BigUint {
        UnsignedAmount::get_normalization_factor()
    }

    #[staticmethod]
    fn from_v1(amount: BigUint) -> Self {
        Self(UnsignedAmount::from_v1(amount))
    }

    #[staticmethod]
    fn from_v2(amount: BigUint) -> Self {
        Self(UnsignedAmount::from_v2(amount))
    }

    #[staticmethod]
    #[pyo3(signature = (amount, *, version))]
    fn from_version(amount: BigUint, version: &Bound<'_, PyInt>) -> PyResult<Self> {
        let version = TokenAmountVersion::from_u8(version.extract()?)
            .ok_or_else(|| PyValueError::new_err(format!("unknown version: {version}")))?;
        Ok(Self(UnsignedAmount::from_version(amount, version)))
    }

    #[staticmethod]
    fn zero() -> Self {
        Self(UnsignedAmount::ZERO)
    }

    #[staticmethod]
    fn parse(s: &str) -> PyResult<Self> {
        UnsignedAmount::parse(s)
            .map(Self::new)
            .map_err(|err| PyValueError::new_err(err.to_string()))
    }

    fn is_v1(&self) -> bool {
        self.0.is_v1()
    }

    fn is_v2(&self) -> bool {
        self.0.is_v2()
    }

    fn normalized(&self) -> &BigUint {
        self.0.normalized()
    }

    fn raw(&self) -> &BigUint {
        self.0.raw()
    }

    fn to_signed(&self) -> PySignedAmount {
        PySignedAmount::new(self.0.to_signed())
    }

    fn to_v1(&self) -> PyResult<Self> {
        self.0
            .to_v1()
            .map(|v1| Self::new(v1.into_owned()))
            .ok_or_else(|| {
                PyAssertionError::new_err(format!(
                    "cannot denormalize value, would truncate ({:?})",
                    self.0,
                ))
            })
    }

    fn maybe_to_v1(&self) -> Option<Self> {
        self.0.to_v1().map(|v1| Self::new(v1.into_owned()))
    }

    fn to_v2(&self) -> Self {
        Self::new(self.0.to_v2().into_owned())
    }

    fn to_version(&self, version: &Bound<'_, PyInt>) -> PyResult<Self> {
        let version = TokenAmountVersion::from_u8(version.extract()?)
            .ok_or_else(|| PyValueError::new_err(format!("unknown version: {version}")))?;
        self.0
            .to_version(version)
            .map(|amount| Self::new(amount.into_owned()))
            .ok_or_else(|| {
                PyAssertionError::new_err(format!(
                    "cannot denormalize value, would truncate ({:?})",
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

    fn __richcmp__(&self, other: &Bound<'_, PyAny>, op: pyo3::basic::CompareOp) -> PyResult<bool> {
        // Accept any object and raise `TypeError` on a non-`UnsignedAmount` operand so that
        // `==`/`!=` against a foreign type fail loudly. PyO3 returns `NotImplemented` automatically
        // which would let Python fall back to object identity and silently yield a wrong boolean.
        if let Ok(other) = other.cast_exact::<PyUnsignedAmount>() {
            Ok(op.matches(self.0.cmp(&other.get().0)))
        } else {
            let type_name = other
                .get_type()
                .name()
                .map(|n| n.to_string())
                .unwrap_or_else(|_| "<unknown type>".to_owned());
            Err(PyTypeError::new_err(format!(
                "comparison not supported between instances of 'UnsignedAmount' and '{type_name}'",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use htr_lib::SignedAmount;
    use num_bigint::BigInt;

    const TEN_TO_THE_SIXTEENTH: u64 = 10u64.pow(16);

    fn init() {
        UnsignedAmount::set_decimal_places(2, 18)
    }

    fn big(n: u64) -> BigUint {
        BigUint::from(n)
    }

    #[test]
    fn py_from_version_unknown_raises_value_error() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let version = 3i32.into_pyobject(py).unwrap();
            let Err(err) = PyUnsignedAmount::from_version(big(5), &version) else {
                panic!("expected ValueError on unknown version");
            };
            assert!(err.is_instance_of::<PyValueError>(py));
            assert_eq!(err.value(py).to_string(), "unknown version: 3");
        });
    }

    #[test]
    fn py_from_version_v1_constructs() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let version = 1i32.into_pyobject(py).unwrap();
            let amount = PyUnsignedAmount::from_version(big(5), &version).unwrap();
            assert!(amount.is_v1());
            assert_eq!(amount.normalized(), &big(5 * TEN_TO_THE_SIXTEENTH));
        });
    }

    #[test]
    fn py_from_version_v2_constructs() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let version = 2i32.into_pyobject(py).unwrap();
            let amount = PyUnsignedAmount::from_version(big(5), &version).unwrap();
            assert!(amount.is_v2());
            assert_eq!(amount.normalized(), &big(5));
        });
    }

    #[test]
    fn py_parse_creates_v2_value() {
        init();
        let amount = PyUnsignedAmount::parse("1.5").unwrap();
        assert!(amount.is_v2());
        assert_eq!(amount.normalized(), &big(1_500_000_000_000_000_000));
    }

    // A fractional part exceeding the V2 precision surfaces as a Python `ValueError` carrying
    // the parse error's message.
    #[test]
    fn py_parse_too_many_decimal_places_raises_value_error() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let Err(err) = PyUnsignedAmount::parse("0.0000000000000000001") else {
                panic!("expected ValueError on excess precision");
            };
            assert!(err.is_instance_of::<PyValueError>(py));
            assert_eq!(
                err.value(py).to_string(),
                "too many decimal places: 19 (at most 18)"
            );
        });
    }

    // Goes through Python's `repr()` so the `tp_repr` slot is exercised: `__repr__` exposes
    // the inner enum's Debug form — variant tag plus `BigUint` fields. V1 carries both `raw`
    // and its V2-scaled `normalized`; V2 carries only `normalized`.
    #[test]
    fn py_repr_pins_debug_form_per_variant() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let v1 = Bound::new(py, PyUnsignedAmount::from_v1(big(5))).unwrap();
            let repr: String = v1.as_any().repr().unwrap().extract().unwrap();
            assert_eq!(repr, "V1 { raw: 5, normalized: 50000000000000000 }");

            let v2 = Bound::new(py, PyUnsignedAmount::from_v2(big(5))).unwrap();
            let repr: String = v2.as_any().repr().unwrap().extract().unwrap();
            assert_eq!(repr, "V2 { normalized: 5 }");
        });
    }

    // Goes through Python's `str()` so the `tp_str` slot is exercised: `__str__` renders the
    // native encoding as a fixed-point decimal — V1's `raw` with two fractional digits, V2's
    // `normalized` with eighteen.
    #[test]
    fn py_str_renders_fixed_point_decimal_per_variant() {
        init();
        Python::initialize();
        Python::attach(|py| {
            for (amount, expected) in [
                (PyUnsignedAmount::from_v1(big(0)), "0.00"),
                (PyUnsignedAmount::from_v1(big(5)), "0.05"),
                (PyUnsignedAmount::from_v1(big(100)), "1.00"),
                (PyUnsignedAmount::from_v1(big(12345)), "123.45"),
                (PyUnsignedAmount::from_v2(big(0)), "0.000000000000000000"),
                (PyUnsignedAmount::from_v2(big(5)), "0.000000000000000005"),
                (
                    PyUnsignedAmount::from_v2(big(10u64.pow(18))),
                    "1.000000000000000000",
                ),
            ] {
                let bound = Bound::new(py, amount).unwrap();
                let rendered: String = bound.as_any().str().unwrap().extract().unwrap();
                assert_eq!(rendered, expected);
            }
        });
    }

    // Goes through Python attribute lookup so the `#[pymethods]` wiring is exercised:
    // a swap between `__add__` and `__sub__` in the source would still compile, and the
    // inner `Add` tests above would still pass — only this test would catch it.
    #[test]
    fn py_add_forwards_through_python_dispatch() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let a = Bound::new(py, PyUnsignedAmount::new(UnsignedAmount::from_v2(big(2)))).unwrap();
            let b = Bound::new(py, PyUnsignedAmount::new(UnsignedAmount::from_v2(big(3)))).unwrap();
            let result = a.call_method1("__add__", (b,)).unwrap();
            let result: PyRef<'_, PyUnsignedAmount> = result.extract().unwrap();
            assert!(result.is_v2());
            assert_eq!(result.normalized(), &big(5));
        });
    }

    #[test]
    fn py_sub_forwards_through_python_dispatch() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let a =
                Bound::new(py, PyUnsignedAmount::new(UnsignedAmount::from_v2(big(10)))).unwrap();
            let b = Bound::new(py, PyUnsignedAmount::new(UnsignedAmount::from_v2(big(3)))).unwrap();
            let result = a.call_method1("__sub__", (b,)).unwrap();
            let result: PyRef<'_, PyUnsignedAmount> = result.extract().unwrap();
            assert!(result.is_v2());
            assert_eq!(result.normalized(), &big(7));
        });
    }

    #[test]
    fn py_same_type_comparisons_through_operator_dispatch() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let a = Bound::new(py, PyUnsignedAmount::new(UnsignedAmount::from_v2(big(5)))).unwrap();
            let b = Bound::new(py, PyUnsignedAmount::new(UnsignedAmount::from_v2(big(5)))).unwrap();
            let c = Bound::new(py, PyUnsignedAmount::new(UnsignedAmount::from_v2(big(6)))).unwrap();
            let a_any = a.as_any();
            let b_any = b.as_any();
            let c_any = c.as_any();

            assert!(a_any.eq(b_any).unwrap());
            assert!(!a_any.ne(b_any).unwrap());
            assert!(a_any.le(b_any).unwrap());
            assert!(a_any.ge(b_any).unwrap());
            assert!(a_any.lt(c_any).unwrap());
            assert!(!a_any.gt(c_any).unwrap());
        });
    }

    // Exercises the full `tp_richcompare` dispatch path used by Python's `==` / `<` / etc.
    // The invariant: a cross-type comparison surfaces `TypeError` through the type slot,
    // so `amount == 5` raises end-to-end and Python never falls back to identity equality.
    #[test]
    fn py_comparison_with_int_raises_type_error_via_python_operators() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let amount =
                Bound::new(py, PyUnsignedAmount::new(UnsignedAmount::from_v2(big(5)))).unwrap();
            let other = 5i32.into_pyobject(py).unwrap();
            let amount_any = amount.as_any();
            let other_any = other.as_any();
            let expected_msg =
                "comparison not supported between instances of 'UnsignedAmount' and 'int'";

            for (op, result) in [
                ("==", amount_any.eq(other_any)),
                ("!=", amount_any.ne(other_any)),
                ("<", amount_any.lt(other_any)),
                ("<=", amount_any.le(other_any)),
                (">", amount_any.gt(other_any)),
                (">=", amount_any.ge(other_any)),
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
    // type-name in the error confirms `cast_exact::<PyUnsignedAmount>` rejects `PySignedAmount`
    // and surfaces it as the foreign type, not the catch-all `"unknown type"` fallback.
    #[test]
    fn py_comparison_with_signed_amount_raises_type_error() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let amount =
                Bound::new(py, PyUnsignedAmount::new(UnsignedAmount::from_v2(big(5)))).unwrap();
            let signed =
                Bound::new(py, PySignedAmount::new(SignedAmount::new(BigInt::from(5)))).unwrap();
            let err = amount
                .as_any()
                .eq(signed.as_any())
                .expect_err("expected TypeError when comparing UnsignedAmount with SignedAmount");
            assert!(err.is_instance_of::<PyTypeError>(py));
            assert_eq!(
                err.value(py).to_string(),
                "comparison not supported between instances of 'UnsignedAmount' and 'SignedAmount'"
            );
        });
    }

    #[test]
    fn py_to_v1_on_v2_multiple_converts_to_v1() {
        init();
        Python::initialize();
        Python::attach(|_py| {
            let amount =
                PyUnsignedAmount::new(UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH)));
            let v1 = amount.to_v1().expect("multiple of factor converts");
            assert!(v1.is_v1());
            assert_eq!(v1.raw(), &big(5));
            assert_eq!(v1.normalized(), &big(5 * TEN_TO_THE_SIXTEENTH));
        });
    }

    // The inner `to_v1` reports a non-representable value as `None`; the Python
    // wrapper has to lift that into `AssertionError` carrying the offending
    // value. Pin both the exception type and the full Debug-formatted message
    // so a change to the variant's Debug repr — which would silently shift the
    // user-visible error string — also fails this test.
    #[test]
    fn py_to_v1_on_v2_non_multiple_raises_assertion_error() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let amount =
                PyUnsignedAmount::new(UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH + 1)));
            let Err(err) = amount.to_v1() else {
                panic!("expected AssertionError on non-divisible to_v1");
            };
            assert!(err.is_instance_of::<PyAssertionError>(py));
            assert_eq!(
                err.value(py).to_string(),
                "cannot denormalize value, would truncate (V2 { normalized: 50000000000000001 })"
            );
        });
    }

    // `maybe_to_v1` is the `Option`-returning sibling of `to_v1`: a V2 that is a
    // multiple of the factor yields `Some` V1 carrying the divided-down `raw`.
    #[test]
    fn py_maybe_to_v1_on_v2_multiple_returns_some_v1() {
        init();
        Python::initialize();
        Python::attach(|_py| {
            let amount =
                PyUnsignedAmount::new(UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH)));
            let v1 = amount.maybe_to_v1().expect("multiple of factor converts");
            assert!(v1.is_v1());
            assert_eq!(v1.raw(), &big(5));
            assert_eq!(v1.normalized(), &big(5 * TEN_TO_THE_SIXTEENTH));
        });
    }

    // The divergence from `to_v1`: a non-representable value is reported as `None`,
    // not surfaced as `AssertionError`.
    #[test]
    fn py_maybe_to_v1_on_v2_non_multiple_returns_none() {
        init();
        Python::initialize();
        Python::attach(|_py| {
            let amount =
                PyUnsignedAmount::new(UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH + 1)));
            assert!(amount.maybe_to_v1().is_none());
        });
    }

    #[test]
    fn py_to_v2_converts_v1_to_v2() {
        init();
        Python::initialize();
        Python::attach(|_py| {
            let amount = PyUnsignedAmount::new(UnsignedAmount::from_v1(big(5)));
            let v2 = amount.to_v2();
            assert!(v2.is_v2());
            assert_eq!(v2.raw(), &big(5 * TEN_TO_THE_SIXTEENTH));
            assert_eq!(v2.normalized(), &big(5 * TEN_TO_THE_SIXTEENTH));
        });
    }

    #[test]
    fn py_to_version_unknown_raises_value_error() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let version = 3i32.into_pyobject(py).unwrap();
            let amount = PyUnsignedAmount::new(UnsignedAmount::from_v2(big(5)));
            let Err(err) = amount.to_version(&version) else {
                panic!("expected ValueError on unknown version");
            };
            assert!(err.is_instance_of::<PyValueError>(py));
            assert_eq!(err.value(py).to_string(), "unknown version: 3");
        });
    }

    #[test]
    fn py_to_version_v1_on_multiple_converts() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let version = 1i32.into_pyobject(py).unwrap();
            let amount =
                PyUnsignedAmount::new(UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH)));
            let v1 = amount.to_version(&version).unwrap();
            assert!(v1.is_v1());
            assert_eq!(v1.raw(), &big(5));
            assert_eq!(v1.normalized(), &big(5 * TEN_TO_THE_SIXTEENTH));
        });
    }

    #[test]
    fn py_to_version_v2_converts() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let version = 2i32.into_pyobject(py).unwrap();
            let amount = PyUnsignedAmount::new(UnsignedAmount::from_v1(big(5)));
            let v2 = amount.to_version(&version).unwrap();
            assert!(v2.is_v2());
            assert_eq!(v2.normalized(), &big(5 * TEN_TO_THE_SIXTEENTH));
        });
    }

    // The inner `to_version` reports a non-representable V1 target as `None`; the
    // Python wrapper lifts that into `AssertionError` carrying the offending value,
    // mirroring `to_v1`. Pinning the full Debug-formatted message means a change to
    // the variant's Debug repr also fails here.
    #[test]
    fn py_to_version_v1_on_non_multiple_raises_assertion_error() {
        init();
        Python::initialize();
        Python::attach(|py| {
            let version = 1i32.into_pyobject(py).unwrap();
            let amount =
                PyUnsignedAmount::new(UnsignedAmount::from_v2(big(5 * TEN_TO_THE_SIXTEENTH + 1)));
            let Err(err) = amount.to_version(&version) else {
                panic!("expected AssertionError on non-divisible to_version");
            };
            assert!(err.is_instance_of::<PyAssertionError>(py));
            assert_eq!(
                err.value(py).to_string(),
                "cannot denormalize value, would truncate (V2 { normalized: 50000000000000001 })"
            );
        });
    }
}
