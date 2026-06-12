//! The fused batch script pipeline: raw transaction bytes in, per-input script results out,
//! with every step — parsing, sighash, dependency resolution, evaluation — running natively
//! in one GIL-released call.
//!
//! Dependency resolution is tiered: outputs are taken from another tx of the same batch
//! (spend chains during sync), from caller-supplied vertex bytes (the Python cache layer's
//! unflushed entries, second call), or read directly from RocksDB through the shared primary
//! handle. A tx with any unresolvable input is reported back instead of evaluated — the
//! Python side keeps its fallback paths, so rejection semantics never depend on this code.

use std::collections::HashMap;
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::script::{self, OpcodesVersion, ScriptConfig, ScriptJob, interpreter};
use crate::storage::{Db, RocksDb};
use crate::vertex::{Parsed, parse, sighash_preimage};

/// One input's raw evaluation result: `None` (valid) or `(kind, message)`.
type RawResult = Option<(String, String)>;

/// Per-tx outcome statuses.
pub const STATUS_EVALUATED: u8 = 0;
pub const STATUS_UNRESOLVED: u8 = 1;
pub const STATUS_PARSE_FAILED: u8 = 2;

/// `(status, per-input results, missing dep hashes)`.
type TxOutcome = (u8, Vec<RawResult>, Vec<Vec<u8>>);

/// The outputs of a resolved dependency: `(value, script)` per output index.
struct DepOutputs {
    outputs: Vec<(u64, Vec<u8>)>,
}

impl DepOutputs {
    fn from_parsed(parsed: &Parsed) -> Self {
        let outputs = parsed
            .outputs
            .iter()
            .map(|(value, script, _)| (*value, script.clone()))
            .collect();
        Self { outputs }
    }
}

/// Resolve every unique dependency hash: batch first, then supplied bytes, then a native
/// RocksDB read of the tx column family. Unresolvable (absent or unparseable) hashes are
/// simply missing from the returned map.
fn resolve_deps(
    parsed_txs: &[Option<Parsed>],
    supplied: &[Option<Parsed>],
    db: Option<&Arc<Db>>,
    tx_cf: &str,
) -> HashMap<Vec<u8>, DepOutputs> {
    let mut deps: HashMap<Vec<u8>, DepOutputs> = HashMap::new();
    for parsed in parsed_txs.iter().chain(supplied.iter()).flatten() {
        deps.entry(parsed.hash.clone())
            .or_insert_with(|| DepOutputs::from_parsed(parsed));
    }

    let mut unknown: Vec<Vec<u8>> = Vec::new();
    for parsed in parsed_txs.iter().flatten() {
        for (tx_id, _, _) in &parsed.inputs {
            if !deps.contains_key(tx_id) && !unknown.contains(tx_id) {
                unknown.push(tx_id.clone());
            }
        }
    }
    let Some(db) = db else {
        return deps;
    };
    let Some(handle) = db.cf_handle(tx_cf) else {
        return deps;
    };
    let fetched: Vec<(Vec<u8>, Option<DepOutputs>)> = unknown
        .into_par_iter()
        .map(|hash| {
            let outputs = db
                .get_cf(&handle, &hash)
                .ok()
                .flatten()
                .and_then(|bytes| parse(&bytes))
                .map(|parsed| DepOutputs::from_parsed(&parsed));
            (hash, outputs)
        })
        .collect();
    for (hash, outputs) in fetched {
        if let Some(outputs) = outputs {
            deps.insert(hash, outputs);
        }
    }
    deps
}

/// Build the script jobs for one parsed tx, or report the hashes that block it.
fn build_jobs(
    data: &[u8],
    parsed: &Parsed,
    deps: &HashMap<Vec<u8>, DepOutputs>,
    opcodes_version: OpcodesVersion,
) -> Result<Vec<ScriptJob>, Vec<Vec<u8>>> {
    let mut missing: Vec<Vec<u8>> = Vec::new();
    // sha256 of the spliced preimage: `get_sighash_all_data`, computed once per tx
    let sighash_all_data = Sha256::digest(sighash_preimage(data, parsed)).to_vec();
    // OP_FIND_P2PKH (V1 only) is the sole opcode reading the tx outputs
    let tx_outputs: Vec<(u64, Vec<u8>)> = if opcodes_version == OpcodesVersion::V1 {
        parsed
            .outputs
            .iter()
            .map(|(value, script, _)| (*value, script.clone()))
            .collect()
    } else {
        vec![]
    };

    let mut jobs = Vec::with_capacity(parsed.inputs.len());
    for (tx_id, index, input_data) in &parsed.inputs {
        let Some(dep) = deps.get(tx_id) else {
            if !missing.contains(tx_id) {
                missing.push(tx_id.clone());
            }
            continue;
        };
        let Some((value, script)) = dep.outputs.get(*index as usize) else {
            // out-of-range spent index: the fresh Python path raises the canonical error
            return Err(vec![]);
        };
        jobs.push(ScriptJob {
            input_data: input_data.clone(),
            output_script: script.clone(),
            sighash_all_data: sighash_all_data.clone(),
            tx_timestamp: parsed.timestamp as i64,
            spent_output_value: *value,
            tx_outputs: tx_outputs.clone(),
            opcodes_version: match opcodes_version {
                OpcodesVersion::V1 => 1,
                OpcodesVersion::V2 => 2,
            },
        });
    }
    if missing.is_empty() {
        Ok(jobs)
    } else {
        Err(missing)
    }
}

/// Evaluate the input scripts of a batch of serialized transactions, end to end in Rust.
///
/// Each item is one tx's wire bytes. `supplied_deps` are extra serialized vertices to resolve
/// spends against (besides the batch itself and, when `db` is given, the tx column family of
/// the shared RocksDB handle). Returns one `(status, results, missing)` tuple per item:
/// status 0 = evaluated (one result per input, in input order), status 1 = unresolvable
/// dependencies (their hashes listed; possibly empty when the blocker is not a fetchable dep,
/// e.g. an out-of-range spent index), status 2 = the tx bytes themselves are unsupported.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn verify_scripts_from_bytes(
    py: Python<'_>,
    items: Vec<Vec<u8>>,
    supplied_deps: Vec<Vec<u8>>,
    db: Option<PyRef<'_, RocksDb>>,
    tx_cf: String,
    opcodes_version: u8,
    max_size: usize,
    max_multisig_pubkeys: i64,
    max_multisig_signatures: i64,
    p2pkh_version_byte: Vec<u8>,
    num_workers: usize,
) -> PyResult<Vec<TxOutcome>> {
    let version = match opcodes_version {
        1 => OpcodesVersion::V1,
        2 => OpcodesVersion::V2,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown opcodes_version: {other}"
            )));
        }
    };
    let config = ScriptConfig {
        max_multisig_pubkeys,
        max_multisig_signatures,
        p2pkh_version_byte,
    };
    // The native handle is cloned out while attached (PyRef is not Send); the Arc is.
    let native = db.as_ref().and_then(|d| d.native());

    let outcomes = py.detach(|| {
        let pool = script::thread_pool(num_workers);
        pool.install(|| {
            let parsed_txs: Vec<Option<Parsed>> = items
                .par_iter()
                .map(|data| {
                    if data.len() > max_size {
                        return None;
                    }
                    parse(data)
                })
                .collect();
            let supplied: Vec<Option<Parsed>> = supplied_deps
                .par_iter()
                .map(|data| {
                    if data.len() > max_size {
                        return None;
                    }
                    parse(data)
                })
                .collect();

            let deps = resolve_deps(&parsed_txs, &supplied, native.as_ref(), &tx_cf);

            // Build jobs per tx, then flatten for evaluation: single-input txs dominate, so
            // load-balancing across all inputs of all txs beats parallelizing per tx.
            let mut outcomes: Vec<TxOutcome> = Vec::with_capacity(items.len());
            let mut flat: Vec<(usize, ScriptJob)> = Vec::new();
            for (tx_index, (data, parsed)) in items.iter().zip(parsed_txs.iter()).enumerate() {
                let Some(parsed) = parsed else {
                    outcomes.push((STATUS_PARSE_FAILED, vec![], vec![]));
                    continue;
                };
                match build_jobs(data, parsed, &deps, version) {
                    Ok(jobs) => {
                        outcomes.push((STATUS_EVALUATED, vec![], vec![]));
                        for job in jobs {
                            flat.push((tx_index, job));
                        }
                    }
                    Err(missing) => {
                        outcomes.push((STATUS_UNRESOLVED, vec![], missing));
                    }
                }
            }

            let results: Vec<(usize, RawResult)> = flat
                .par_iter()
                .map(|(tx_index, job)| {
                    let result = match interpreter::eval_job(job, version, &config) {
                        Ok(()) => None,
                        Err(e) => Some((e.kind.python_name().to_string(), e.message)),
                    };
                    (*tx_index, result)
                })
                .collect();
            for (tx_index, result) in results {
                outcomes[tx_index].1.push(result);
            }
            outcomes
        })
    });
    Ok(outcomes)
}

#[cfg(test)]
mod tests;
