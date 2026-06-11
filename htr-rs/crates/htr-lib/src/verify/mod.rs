//! Stateless vertex verification checks: faithful ports of the storage-free checks in
//! `hathor/verification/{vertex_verifier,transaction_verifier}.py`.
//!
//! Same discipline as the script interpreter: Python remains the authoritative consensus
//! reference, every error maps to the exact Python exception class (by name), and message
//! text is debug-only. Each check is exposed as its own pyfunction so they can be migrated,
//! differential-tested and composed into batches independently.

use pyo3::prelude::*;

/// A check failure: the Python exception class name plus a debug-only message.
pub struct CheckError {
    pub kind: &'static str,
    pub message: String,
}

impl CheckError {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn into_py(self) -> (String, String) {
        (self.kind.to_string(), self.message)
    }
}

const TOKEN_INDEX_MASK: i64 = 0b0111_1111;
const TOKEN_AUTHORITY_MASK: i64 = 0b1000_0000;

/// One output's checked fields: `(value, script_len, token_data)`. The script bytes
/// themselves are not needed by these checks, only the length.
type OutputFields = (i64, u64, i64);

/// `VertexVerifier.verify_outputs` (which runs `verify_number_of_outputs` first): no hathor
/// authority UTXOs, positive values, script size below the limit — first failure wins, in
/// the exact Python check order.
fn check_outputs(
    outputs: &[OutputFields],
    max_num_outputs: u64,
    max_output_script_size: u64,
) -> Option<CheckError> {
    if outputs.len() as u64 > max_num_outputs {
        let message = "Maximum number of outputs exceeded";
        return Some(CheckError::new("TooManyOutputs", message));
    }
    for (index, &(value, script_len, token_data)) in outputs.iter().enumerate() {
        // no hathor authority UTXO
        if token_data & TOKEN_INDEX_MASK == 0 && token_data & TOKEN_AUTHORITY_MASK != 0 {
            let message = format!("Cannot have authority UTXO for hathor tokens: index {index}");
            return Some(CheckError::new("InvalidToken", message));
        }

        // output value must be positive
        if value <= 0 {
            let message = format!(
                "Output value must be a positive integer. Value: {value} and index: {index}"
            );
            return Some(CheckError::new("InvalidOutputValue", message));
        }

        if script_len > max_output_script_size {
            let message = format!("size: {script_len} and max-size: {max_output_script_size}");
            return Some(CheckError::new("InvalidOutputScriptSize", message));
        }
    }
    None
}

/// `TransactionVerifier.verify_output_token_indexes`: every output's token index must point
/// into the tx's tokens list (index 0 is the implicit HTR entry, so `index <= len(tokens)`).
fn check_output_token_indexes(token_data_list: &[i64], tokens_count: u64) -> Option<CheckError> {
    for &token_data in token_data_list {
        let token_index = token_data & TOKEN_INDEX_MASK;
        // token_data & 0x7F is always in 0..=127, so the cast to u64 is lossless.
        if token_index as u64 > tokens_count {
            let message = format!("token uid index not available: index {token_index}");
            return Some(CheckError::new("InvalidToken", message));
        }
    }
    None
}

/// `VertexVerifier.verify_pow`'s comparison: the vertex hash, read as a big-endian integer,
/// must be strictly below the target. The target itself is computed in Python
/// (`vertex.get_target()`, a float expression) and marshalled as minimal big-endian bytes —
/// porting the float math would risk last-ulp divergence from CPython's libm `pow`.
fn check_pow(hash: &[u8], target_be: &[u8]) -> Option<CheckError> {
    if numeric_less_than(hash, target_be) {
        return None;
    }
    let message = format!(
        "Transaction has invalid data (0x{} < 0x{})",
        hex(hash),
        hex(target_be)
    );
    Some(CheckError::new("PowError", message))
}

/// Compare two big-endian unsigned integers of arbitrary (possibly different) lengths.
fn numeric_less_than(left: &[u8], right: &[u8]) -> bool {
    let left = strip_leading_zeros(left);
    let right = strip_leading_zeros(right);
    if left.len() != right.len() {
        return left.len() < right.len();
    }
    left < right
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[pyfunction]
pub fn verify_outputs(
    outputs: Vec<OutputFields>,
    max_num_outputs: u64,
    max_output_script_size: u64,
) -> Option<(String, String)> {
    check_outputs(&outputs, max_num_outputs, max_output_script_size).map(CheckError::into_py)
}

#[pyfunction]
pub fn verify_output_token_indexes(
    token_data_list: Vec<i64>,
    tokens_count: u64,
) -> Option<(String, String)> {
    check_output_token_indexes(&token_data_list, tokens_count).map(CheckError::into_py)
}

#[pyfunction]
pub fn verify_pow(hash: Vec<u8>, target_be: Vec<u8>) -> Option<(String, String)> {
    check_pow(&hash, &target_be).map(CheckError::into_py)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(error: Option<CheckError>) -> Option<&'static str> {
        error.map(|e| e.kind)
    }

    #[test]
    fn test_outputs_valid() {
        let outputs = vec![(100, 25, 0), (1, 1024, 1), (i64::MAX, 0, 127)];
        assert!(check_outputs(&outputs, 255, 1024).is_none());
    }

    #[test]
    fn test_outputs_empty() {
        assert!(check_outputs(&[], 255, 1024).is_none());
    }

    #[test]
    fn test_outputs_too_many() {
        let outputs = vec![(1, 0, 0); 3];
        assert_eq!(
            kind(check_outputs(&outputs, 2, 1024)),
            Some("TooManyOutputs")
        );
        // the number check runs before any per-output check
        let outputs = vec![(0, 0, 0); 3];
        assert_eq!(
            kind(check_outputs(&outputs, 2, 1024)),
            Some("TooManyOutputs")
        );
    }

    #[test]
    fn test_outputs_hathor_authority() {
        // token index 0 + authority bit -> InvalidToken
        assert_eq!(
            kind(check_outputs(&[(1, 0, 0x80)], 255, 1024)),
            Some("InvalidToken")
        );
        // authority over a custom token (index != 0) passes this check
        assert!(check_outputs(&[(1, 0, 0x81)], 255, 1024).is_none());
    }

    #[test]
    fn test_outputs_non_positive_value() {
        assert_eq!(
            kind(check_outputs(&[(0, 0, 0)], 255, 1024)),
            Some("InvalidOutputValue")
        );
        assert_eq!(
            kind(check_outputs(&[(-5, 0, 0)], 255, 1024)),
            Some("InvalidOutputValue")
        );
        // the authority check runs first for the same output
        assert_eq!(
            kind(check_outputs(&[(0, 0, 0x80)], 255, 1024)),
            Some("InvalidToken")
        );
    }

    #[test]
    fn test_outputs_script_too_large() {
        assert_eq!(
            kind(check_outputs(&[(1, 1025, 0)], 255, 1024)),
            Some("InvalidOutputScriptSize")
        );
        // value check runs before script size for the same output
        assert_eq!(
            kind(check_outputs(&[(0, 1025, 0)], 255, 1024)),
            Some("InvalidOutputValue")
        );
    }

    #[test]
    fn test_outputs_first_failure_wins() {
        let outputs = vec![(1, 0, 0), (0, 0, 0), (1, 9999, 0)];
        assert_eq!(
            kind(check_outputs(&outputs, 255, 1024)),
            Some("InvalidOutputValue")
        );
    }

    #[test]
    fn test_token_indexes() {
        // index 0 (HTR) is always fine; index == len(tokens) is fine; above is not.
        assert!(check_output_token_indexes(&[0, 1, 2], 2).is_none());
        assert_eq!(
            kind(check_output_token_indexes(&[3], 2)),
            Some("InvalidToken")
        );
        // the authority bit does not affect the index
        assert!(check_output_token_indexes(&[0x80 | 2], 2).is_none());
        assert_eq!(
            kind(check_output_token_indexes(&[0x80 | 3], 2)),
            Some("InvalidToken")
        );
        assert!(check_output_token_indexes(&[], 0).is_none());
        // Python's negative-int `&` matches two's complement: -1 & 0x7F == 127.
        assert_eq!(
            kind(check_output_token_indexes(&[-1], 2)),
            Some("InvalidToken")
        );
    }

    #[test]
    fn test_pow() {
        // hash < target -> ok
        assert!(check_pow(&[0x00, 0x01], &[0x00, 0x02]).is_none());
        // equal -> PowError (strictly less than)
        assert_eq!(kind(check_pow(&[0x01], &[0x01])), Some("PowError"));
        // greater -> PowError
        assert_eq!(kind(check_pow(&[0x02], &[0x01])), Some("PowError"));
        // leading zeros are insignificant
        assert!(check_pow(&[0x00, 0x00, 0x01], &[0x02]).is_none());
        assert_eq!(kind(check_pow(&[0x01, 0x00], &[0xFF])), Some("PowError"));
        // a target wider than 32 bytes (weight < 0) is bigger than any hash
        assert!(check_pow(&[0xFF; 32], &[0x01; 33]).is_none());
        // zero target (weight == 256) rejects every hash, including the zero hash
        assert_eq!(kind(check_pow(&[0x00; 32], &[0x00])), Some("PowError"));
        assert_eq!(kind(check_pow(&[0x00; 32], &[])), Some("PowError"));
    }
}
