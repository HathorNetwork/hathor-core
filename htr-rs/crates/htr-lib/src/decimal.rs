//! Fixed-point decimal rendering for token amounts.
//!
//! Token amounts are stored as integers; the human-facing form places a decimal point a
//! fixed number of digits from the right, where the count depends on the amount's version.

use num_bigint::BigUint;
use std::fmt;

/// Render an unsigned integer `magnitude` as a fixed-point decimal: at least one digit before
/// the `.`, and exactly `decimal_places` digits after it. With zero decimal places there is no
/// fractional part, so the point is omitted and a bare integer is rendered.
pub(crate) fn format_fixed_point(magnitude: &BigUint, decimal_places: u32) -> String {
    let mut digits = magnitude.to_string();
    if decimal_places == 0 {
        return digits;
    }
    if digits.len() <= decimal_places as usize {
        let padding = decimal_places as usize + 1 - digits.len();
        digits.insert_str(0, &"0".repeat(padding));
    }
    let split = digits.len() - decimal_places as usize;
    format!("{}.{}", &digits[..split], &digits[split..])
}

/// Why a decimal string could not be parsed into a fixed-point integer.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseDecimalError {
    /// A required digit group was empty: the input had no integer digits, or a decimal point
    /// with nothing on one side (e.g. an empty string, `.`, `1.`, `.5`).
    MissingDigits,
    /// The string held a character other than a digit or a single `.`.
    InvalidCharacter,
    /// The string held more than one decimal point.
    MultipleDecimalPoints,
    /// The fractional part had more digits than the target precision can represent.
    TooManyDecimalPlaces { found: usize, max: u32 },
}

impl fmt::Display for ParseDecimalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseDecimalError::MissingDigits => {
                f.write_str("decimal string is missing required digits")
            }
            ParseDecimalError::InvalidCharacter => {
                f.write_str("decimal string contains a non-digit character")
            }
            ParseDecimalError::MultipleDecimalPoints => {
                f.write_str("decimal string contains more than one decimal point")
            }
            ParseDecimalError::TooManyDecimalPlaces { found, max } => {
                write!(f, "too many decimal places: {found} (at most {max})")
            }
        }
    }
}

impl std::error::Error for ParseDecimalError {}

/// Parse a decimal string into the integer it denotes scaled by `10^decimal_places`, the inverse
/// of [`format_fixed_point`]. Accepts a bare integer, or an integer and fractional part separated
/// by a single `.` with digits on both sides; the fractional part may carry at most
/// `decimal_places` digits.
pub(crate) fn parse_fixed_point(
    input: &str,
    decimal_places: u32,
) -> Result<BigUint, ParseDecimalError> {
    let (integer_part, fractional_part) = match input.split_once('.') {
        Some((integer, fractional)) => {
            if fractional.contains('.') {
                return Err(ParseDecimalError::MultipleDecimalPoints);
            }
            if integer.is_empty() || fractional.is_empty() {
                return Err(ParseDecimalError::MissingDigits);
            }
            (integer, fractional)
        }
        None => {
            if input.is_empty() {
                return Err(ParseDecimalError::MissingDigits);
            }
            (input, "")
        }
    };

    let all_digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    if !all_digits(integer_part) || !all_digits(fractional_part) {
        return Err(ParseDecimalError::InvalidCharacter);
    }
    if fractional_part.len() > decimal_places as usize {
        return Err(ParseDecimalError::TooManyDecimalPlaces {
            found: fractional_part.len(),
            max: decimal_places,
        });
    }

    let trailing_zeros = decimal_places as usize - fractional_part.len();
    let mut digits = String::with_capacity(integer_part.len() + decimal_places as usize);
    digits.push_str(integer_part);
    digits.push_str(fractional_part);
    digits.push_str(&"0".repeat(trailing_zeros));
    Ok(digits
        .parse()
        .expect("validated non-empty digit string parses as BigUint"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big(n: u64) -> BigUint {
        BigUint::from(n)
    }

    #[test]
    fn two_decimal_places() {
        assert_eq!(format_fixed_point(&big(0), 2), "0.00");
        assert_eq!(format_fixed_point(&big(5), 2), "0.05");
        assert_eq!(format_fixed_point(&big(45), 2), "0.45");
        assert_eq!(format_fixed_point(&big(100), 2), "1.00");
        assert_eq!(format_fixed_point(&big(12345), 2), "123.45");
    }

    #[test]
    fn eighteen_decimal_places() {
        assert_eq!(format_fixed_point(&big(0), 18), "0.000000000000000000");
        assert_eq!(format_fixed_point(&big(5), 18), "0.000000000000000005");
        assert_eq!(
            format_fixed_point(&big(10u64.pow(18)), 18),
            "1.000000000000000000"
        );
        assert_eq!(
            format_fixed_point(&big(1_500_000_000_000_000_000), 18),
            "1.500000000000000000"
        );
    }

    // With no fractional part the point is omitted, so a bare integer renders without a dangling
    // `.`, and that rendering still round-trips back through the parser.
    #[test]
    fn zero_decimal_places_render_as_bare_integer() {
        assert_eq!(format_fixed_point(&big(0), 0), "0");
        assert_eq!(format_fixed_point(&big(5), 0), "5");
        assert_eq!(format_fixed_point(&big(123), 0), "123");
        assert_eq!(parse_fixed_point("5", 0).unwrap(), big(5));
    }

    #[test]
    fn parse_integer_and_fraction() {
        assert_eq!(parse_fixed_point("0", 18).unwrap(), big(0));
        assert_eq!(parse_fixed_point("1", 18).unwrap(), big(10u64.pow(18)));
        assert_eq!(
            parse_fixed_point("1.5", 18).unwrap(),
            big(1_500_000_000_000_000_000)
        );
        assert_eq!(
            parse_fixed_point("0.000000000000000001", 18).unwrap(),
            big(1)
        );
        assert_eq!(
            parse_fixed_point("1.000000000000000000", 18).unwrap(),
            big(10u64.pow(18))
        );
    }

    // A decimal point requires digits on both sides: a leading or trailing point is rejected.
    #[test]
    fn parse_rejects_empty_side() {
        assert_eq!(
            parse_fixed_point(".5", 18),
            Err(ParseDecimalError::MissingDigits)
        );
        assert_eq!(
            parse_fixed_point("1.", 18),
            Err(ParseDecimalError::MissingDigits)
        );
    }

    // The fractional part is bounded by the target precision: eighteen digits parse, nineteen
    // do not, and the error reports both the count found and the limit.
    #[test]
    fn parse_rejects_excess_decimal_places() {
        assert_eq!(
            parse_fixed_point("0.0000000000000000001", 18),
            Err(ParseDecimalError::TooManyDecimalPlaces { found: 19, max: 18 })
        );
    }

    #[test]
    fn parse_rejects_malformed_input() {
        assert_eq!(
            parse_fixed_point("", 18),
            Err(ParseDecimalError::MissingDigits)
        );
        assert_eq!(
            parse_fixed_point(".", 18),
            Err(ParseDecimalError::MissingDigits)
        );
        assert_eq!(
            parse_fixed_point("-1", 18),
            Err(ParseDecimalError::InvalidCharacter)
        );
        assert_eq!(
            parse_fixed_point("1 000", 18),
            Err(ParseDecimalError::InvalidCharacter)
        );
        assert_eq!(
            parse_fixed_point("abc", 18),
            Err(ParseDecimalError::InvalidCharacter)
        );
        assert_eq!(
            parse_fixed_point("1.2.3", 18),
            Err(ParseDecimalError::MultipleDecimalPoints)
        );
    }

    // Round-trips the rendering: a value formatted at a given precision parses back to itself.
    #[test]
    fn parse_inverts_format() {
        let value = big(1_500_000_000_000_000_000);
        let rendered = format_fixed_point(&value, 18);
        assert_eq!(parse_fixed_point(&rendered, 18).unwrap(), value);
    }
}
