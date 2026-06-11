//! Batch input-script verification.
//!
//! This is a consensus-critical, bit-for-bit port of the Python script interpreter in
//! `hathor/transaction/scripts/{execute,opcode,multi_sig}.py`. Python remains the authoritative
//! reference: every accept/reject decision and every error *category* (which Python exception
//! class would have been raised) must match the Python implementation exactly. Human-readable
//! error messages are debug-only and intentionally not part of consensus.

pub mod crypto;
pub mod interpreter;
pub mod matchers;
pub mod opcodes;

use std::sync::OnceLock;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rayon::prelude::*;

/// Mirrors the kind of Python exception the reference implementation raises.
///
/// The first group maps to `ScriptError` subclasses (`hathorlib.exceptions`), which
/// `execute_script_verification_job` catches and the verifier wraps as `InvalidInputData`.
/// The second group maps to exception types that escape `run_jobs` *unwrapped* in Python
/// (`InvalidScriptError` is a `TxValidationError`, not a `ScriptError`; the rest are raw
/// crash paths reachable from attacker-controlled scripts). Preserving this split is part
/// of consensus: `consensus.py` branches on `InvalidInputData`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    // ScriptError subclasses.
    OutOfData,
    MissingStackItems,
    EqualVerifyFailed,
    FinalStackInvalid,
    OracleChecksigFailed,
    DataIndexError,
    InvalidStackData,
    VerifyFailed,
    TimeLocked,
    Script,
    // Exceptions that escape `run_jobs` unwrapped.
    InvalidScript,
    AssertionFailed,
    StructError,
    IndexError,
    UnicodeDecode,
}

impl ErrorKind {
    /// Name of the Python exception class this kind maps to.
    pub fn python_name(self) -> &'static str {
        match self {
            Self::OutOfData => "OutOfData",
            Self::MissingStackItems => "MissingStackItems",
            Self::EqualVerifyFailed => "EqualVerifyFailed",
            Self::FinalStackInvalid => "FinalStackInvalid",
            Self::OracleChecksigFailed => "OracleChecksigFailed",
            Self::DataIndexError => "DataIndexError",
            Self::InvalidStackData => "InvalidStackData",
            Self::VerifyFailed => "VerifyFailed",
            Self::TimeLocked => "TimeLocked",
            Self::Script => "ScriptError",
            Self::InvalidScript => "InvalidScriptError",
            Self::AssertionFailed => "AssertionError",
            Self::StructError => "StructError",
            Self::IndexError => "IndexError",
            Self::UnicodeDecode => "UnicodeDecodeError",
        }
    }
}

/// A script evaluation failure: the Python exception category plus a debug-only message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalError {
    pub kind: ErrorKind,
    pub message: String,
}

impl EvalError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// Opcode set version, gating the V1-only opcodes exactly like `execute_op_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpcodesVersion {
    V1,
    V2,
}

/// Settings snapshot the opcodes need; passed per batch call so Rust never reads global state.
#[derive(Debug, Clone)]
pub struct ScriptConfig {
    pub max_multisig_pubkeys: i64,
    pub max_multisig_signatures: i64,
    /// Concatenated verbatim when building P2PKH address bytes, exactly like Python.
    pub p2pkh_version_byte: Vec<u8>,
}

/// One input's script evaluation job, extracted field-by-field from the Python
/// `ScriptVerificationJob` dataclass (attribute access keeps the dataclass the single
/// source of truth; all bytes are copied out before the GIL is released).
#[derive(Debug, FromPyObject)]
pub struct ScriptJob {
    pub input_data: Vec<u8>,
    pub output_script: Vec<u8>,
    pub sighash_all_data: Vec<u8>,
    pub tx_timestamp: i64,
    pub spent_output_value: u64,
    pub tx_outputs: Vec<(u64, Vec<u8>)>,
    pub opcodes_version: u8,
}

impl ScriptJob {
    fn version(&self) -> PyResult<OpcodesVersion> {
        match self.opcodes_version {
            1 => Ok(OpcodesVersion::V1),
            2 => Ok(OpcodesVersion::V2),
            other => Err(PyValueError::new_err(format!(
                "unknown opcodes_version: {other}"
            ))),
        }
    }
}

/// The dedicated rayon pool used for script verification. Sized on first use; later calls
/// with a different `num_workers` reuse the existing pool.
fn thread_pool(num_workers: usize) -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_workers.max(1))
            .thread_name(|i| format!("script-verify-{i}"))
            .build()
            .expect("a thread pool with >= 1 threads and no custom start handlers always builds")
    })
}

/// Verify a batch of input scripts in parallel, releasing the GIL for the whole evaluation.
///
/// Returns one entry per job, in order: `None` if the script is valid, otherwise
/// `(kind, message)` where `kind` is the Python exception class name (see [`ErrorKind`])
/// and `message` is debug-only.
#[pyfunction]
pub fn verify_scripts_batch(
    py: Python<'_>,
    jobs: Vec<ScriptJob>,
    max_multisig_pubkeys: i64,
    max_multisig_signatures: i64,
    p2pkh_version_byte: Vec<u8>,
    num_workers: usize,
) -> PyResult<Vec<Option<(String, String)>>> {
    // Validate versions while still attached so a bad job is a Python-visible error.
    let versions = jobs
        .iter()
        .map(ScriptJob::version)
        .collect::<PyResult<Vec<_>>>()?;
    let config = ScriptConfig {
        max_multisig_pubkeys,
        max_multisig_signatures,
        p2pkh_version_byte,
    };

    let results = py.detach(|| {
        let pool = thread_pool(num_workers);
        pool.install(|| {
            jobs.par_iter()
                .zip(versions.par_iter())
                .map(
                    |(job, version)| match interpreter::eval_job(job, *version, &config) {
                        Ok(()) => None,
                        Err(e) => Some((e.kind.python_name().to_string(), e.message)),
                    },
                )
                .collect()
        })
    });
    Ok(results)
}
