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

/// Check identifiers for [`verify_vertex_stateless`], matching the constants on the Python
/// side (`RustVerificationService`).
pub const CHECK_POW: u8 = 0;
pub const CHECK_OUTPUTS: u8 = 1;
pub const CHECK_OUTPUT_TOKEN_INDEXES: u8 = 2;
pub const CHECK_SIGOPS_OUTPUT: u8 = 3;

/// The per-vertex data marshalled once from Python for [`verify_vertex_stateless`].
///
/// Extracted by attribute from the Python `StatelessVertexCheckData` dataclass (same pattern
/// as `ScriptJob`): named fields keep the boundary self-describing and extraction errors
/// name the offending field. Each output is `(value, script, token_data)`.
#[derive(FromPyObject)]
pub struct VertexCheckData {
    outputs: Vec<(i64, Vec<u8>, i64)>,
    tokens_count: u64,
    vertex_hash: Vec<u8>,
    pow_target_be: Vec<u8>,
    max_num_outputs: u64,
    max_output_script_size: u64,
    max_tx_sigops_output: u64,
    max_multisig_pubkeys: u64,
    enable_checkdatasig_count: bool,
}

/// `VertexVerifier.verify_sigops_output` including its limit check: sum the sigops of every
/// output script and compare against the per-tx limit.
fn check_sigops_output(data: &VertexCheckData) -> Option<CheckError> {
    let mut total: u64 = 0;
    for (_, script, _) in &data.outputs {
        match crate::script::sigops::count_sigops(
            script,
            data.max_multisig_pubkeys,
            data.enable_checkdatasig_count,
        ) {
            Ok(count) => total += count,
            Err(e) => {
                return Some(CheckError {
                    kind: e.kind.python_name(),
                    message: e.message,
                });
            }
        }
    }
    if total > data.max_tx_sigops_output {
        let message = format!(
            "TX[{}]: Maximum number of sigops for all outputs exceeded ({total})",
            hex(&data.vertex_hash)
        );
        return Some(CheckError::new("TooManySigOps", message));
    }
    None
}

fn run_check(check: u8, data: &VertexCheckData) -> Option<CheckError> {
    match check {
        CHECK_POW => check_pow(&data.vertex_hash, &data.pow_target_be),
        CHECK_OUTPUTS => {
            let fields: Vec<OutputFields> = data
                .outputs
                .iter()
                .map(|(value, script, token_data)| (*value, script.len() as u64, *token_data))
                .collect();
            check_outputs(&fields, data.max_num_outputs, data.max_output_script_size)
        }
        CHECK_OUTPUT_TOKEN_INDEXES => {
            let token_data_list: Vec<i64> = data
                .outputs
                .iter()
                .map(|(_, _, token_data)| *token_data)
                .collect();
            check_output_token_indexes(&token_data_list, data.tokens_count)
        }
        CHECK_SIGOPS_OUTPUT => check_sigops_output(data),
        _ => unreachable!("check ids are validated before the GIL is released"),
    }
}

/// Run the requested stateless checks for one vertex in a single GIL-released call, in
/// parallel on the shared rayon pool. Returns one entry per requested check, in request
/// order: `None` (passed) or `(kind, message)`. The caller consumes the results in the
/// canonical Python check order, so which error *surfaces* is unaffected by the parallelism.
#[pyfunction]
pub fn verify_vertex_stateless(
    py: Python<'_>,
    checks: Vec<u8>,
    data: VertexCheckData,
    num_workers: usize,
) -> PyResult<Vec<Option<(String, String)>>> {
    use pyo3::exceptions::PyValueError;
    use rayon::prelude::*;

    if let Some(&bad) = checks.iter().find(|&&c| c > CHECK_SIGOPS_OUTPUT) {
        return Err(PyValueError::new_err(format!("unknown check id: {bad}")));
    }
    let results = py.detach(|| {
        let pool = crate::script::thread_pool(num_workers);
        pool.install(|| {
            checks
                .par_iter()
                .map(|&check| run_check(check, &data).map(CheckError::into_py))
                .collect()
        })
    });
    Ok(results)
}

#[cfg(test)]
mod stateless_tests {
    use super::*;

    fn data(outputs: Vec<(i64, Vec<u8>, i64)>, tokens_count: u64) -> VertexCheckData {
        VertexCheckData {
            outputs,
            tokens_count,
            vertex_hash: vec![0xAB; 32],
            pow_target_be: vec![0xFF; 33], // huge target: pow always passes
            max_num_outputs: 255,
            max_output_script_size: 1024,
            max_tx_sigops_output: 1275,
            max_multisig_pubkeys: 20,
            enable_checkdatasig_count: true,
        }
    }

    fn kinds(checks: &[u8], data: &VertexCheckData) -> Vec<Option<&'static str>> {
        checks
            .iter()
            .map(|&c| run_check(c, data).map(|e| e.kind))
            .collect()
    }

    #[test]
    fn test_all_checks_pass() {
        let outputs = vec![(100, vec![0xAC], 1), (5, vec![0x51], 0)];
        let d = data(outputs, 1);
        let all = [
            CHECK_POW,
            CHECK_OUTPUTS,
            CHECK_OUTPUT_TOKEN_INDEXES,
            CHECK_SIGOPS_OUTPUT,
        ];
        assert_eq!(kinds(&all, &d), vec![None, None, None, None]);
    }

    #[test]
    fn test_independent_failures() {
        // value 0 fails OUTPUTS; token index 3 > 1 fails TOKEN_INDEXES; both reported in
        // their own slots so the caller picks the canonical-order winner.
        let outputs = vec![(0, vec![], 3)];
        let d = data(outputs, 1);
        let all = [
            CHECK_POW,
            CHECK_OUTPUTS,
            CHECK_OUTPUT_TOKEN_INDEXES,
            CHECK_SIGOPS_OUTPUT,
        ];
        assert_eq!(
            kinds(&all, &d),
            vec![None, Some("InvalidOutputValue"), Some("InvalidToken"), None]
        );
    }

    #[test]
    fn test_sigops_limit_and_malformed() {
        // 80 outputs of OP_16 OP_CHECKMULTISIG = 1280 sigops > 1275
        let outputs = vec![(1, vec![0x60, 0xAE], 0); 80];
        let d = data(outputs, 0);
        assert_eq!(
            kinds(&[CHECK_SIGOPS_OUTPUT], &d),
            vec![Some("TooManySigOps")]
        );
        // malformed script keeps the walk's error kind
        let d = data(vec![(1, vec![0x00], 0)], 0);
        assert_eq!(
            kinds(&[CHECK_SIGOPS_OUTPUT], &d),
            vec![Some("InvalidScriptError")]
        );
        let d = data(vec![(1, vec![0x05, 0x01], 0)], 0);
        assert_eq!(kinds(&[CHECK_SIGOPS_OUTPUT], &d), vec![Some("OutOfData")]);
    }

    #[test]
    fn test_pow_failure() {
        let mut d = data(vec![(1, vec![], 0)], 0);
        d.pow_target_be = vec![0x00];
        assert_eq!(kinds(&[CHECK_POW], &d), vec![Some("PowError")]);
    }
}
