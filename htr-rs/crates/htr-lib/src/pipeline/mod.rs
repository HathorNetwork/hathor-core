//! The fused batch verification pipeline: raw transaction bytes in, every Rust-side verdict
//! out — parsing, the stateless checks, sighash, dependency resolution, input-sigops
//! counting and full script evaluation, all in one GIL-released call.
//!
//! Dependency resolution is tiered: outputs are taken from another tx of the same batch
//! (spend chains during sync), from caller-supplied vertex bytes (the Python cache layer's
//! unflushed entries, second call), or read directly from RocksDB through the shared primary
//! handle. The hashes fetched from RocksDB are reported back so Python can pre-warm its
//! object cache through the storage's own loader. A tx with any unresolvable input keeps its
//! stateless results and is reported back for the script stage — the Python side keeps every
//! fallback decision, so rejection semantics never depend on this code.

use std::collections::HashMap;
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::script::{self, OpcodesVersion, ScriptConfig, ScriptJob, interpreter, sigops};
use crate::static_meta::{StaticMeta, decode as decode_static};
use crate::storage::{Db, RocksDb};
use crate::verify::{BLOCK_CHECKS, StatelessSettings, TX_CHECKS, VertexCheckData, run_checks};
use crate::vertex::{Parsed, parse, sighash_preimage};

const VERSION_REGULAR_BLOCK: u8 = 0;

/// One verdict: `None` (passed) or `(kind, message)`.
type RawResult = Option<(String, String)>;

/// Per-tx outcome statuses.
pub const STATUS_EVALUATED: u8 = 0;
pub const STATUS_UNRESOLVED: u8 = 1;
pub const STATUS_PARSE_FAILED: u8 = 2;

/// `(status, stateless results, per-input (sigops error, count), per-input script results,
/// missing dep hashes, static metadata)`. Stateless results are present for every parseable
/// vertex (they are dependency-free) in the canonical per-kind check order; sigops/script
/// results only when every dependency resolved. The static-metadata entry —
/// `(min_height, closest_ancestor_block)` — is present for txs whose dependencies' static
/// records were all resolvable (and whose closest-ancestor candidate is unambiguous; see
/// [`compute_tx_static`]); `None` means the Python fallback computes it.
type TxOutcome = (
    u8,
    Vec<RawResult>,
    Vec<(RawResult, u64)>,
    Vec<RawResult>,
    Vec<Vec<u8>>,
    Option<(u64, Vec<u8>)>,
);

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
/// RocksDB read of the tx column family. Returns the map plus the hashes that were fetched
/// from RocksDB (Python pre-warms its object cache with those). Unresolvable hashes are
/// simply missing from the map.
fn resolve_deps(
    parsed_txs: &[Option<Parsed>],
    supplied: &[Option<Parsed>],
    db: Option<&Arc<Db>>,
    tx_cf: &str,
) -> (HashMap<Vec<u8>, DepOutputs>, Vec<Vec<u8>>) {
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
        return (deps, vec![]);
    };
    let Some(handle) = db.cf_handle(tx_cf) else {
        return (deps, vec![]);
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
    let mut fetched_hashes = Vec::new();
    for (hash, outputs) in fetched {
        if let Some(outputs) = outputs {
            deps.insert(hash.clone(), outputs);
            fetched_hashes.push(hash);
        }
    }
    (deps, fetched_hashes)
}

/// The dependency-stage products for one tx: its script jobs and per-input sigops results.
struct TxDepStage {
    jobs: Vec<ScriptJob>,
    sigops: Vec<(RawResult, u64)>,
}

/// Build the script jobs + input-sigops counts for one parsed tx, or report the hashes that
/// block it.
fn build_dep_stage(
    data: &[u8],
    parsed: &Parsed,
    deps: &HashMap<Vec<u8>, DepOutputs>,
    opcodes_version: OpcodesVersion,
    settings: &StatelessSettings,
) -> Result<TxDepStage, Vec<Vec<u8>>> {
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
    let mut sigops_results = Vec::with_capacity(parsed.inputs.len());
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
        let sigops_result = match sigops::get_sigops_count(
            input_data,
            Some(script),
            settings.max_multisig_pubkeys,
            settings.enable_checkdatasig_count,
        ) {
            Ok(count) => (None, count),
            Err(e) => (Some((e.kind.python_name().to_string(), e.message)), 0),
        };
        sigops_results.push(sigops_result);
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
        Ok(TxDepStage {
            jobs,
            sigops: sigops_results,
        })
    } else {
        Err(missing)
    }
}

/// A dependency's static-metadata view, as needed by [`compute_tx_static`].
enum DepStatic {
    Block {
        height: u64,
        min_height: u64,
    },
    Tx {
        min_height: u64,
        closest_ancestor_block: Vec<u8>,
    },
}

/// Batch-local resolver for static-metadata records: in-batch results first, then a native
/// read of the static-metadata column family (memoized).
struct StaticResolver<'a> {
    in_batch: HashMap<Vec<u8>, DepStatic>,
    fetched: HashMap<Vec<u8>, Option<DepStatic>>,
    db: Option<&'a Arc<Db>>,
    static_cf: &'a str,
}

impl<'a> StaticResolver<'a> {
    fn get(&mut self, hash: &[u8]) -> Option<&DepStatic> {
        // Two-phase to satisfy the borrow checker: check in_batch first, then the memoized
        // fetch map (filling it on demand).
        if self.in_batch.contains_key(hash) {
            return self.in_batch.get(hash);
        }
        if !self.fetched.contains_key(hash) {
            let loaded = self.load(hash);
            self.fetched.insert(hash.to_vec(), loaded);
        }
        self.fetched.get(hash).and_then(|entry| entry.as_ref())
    }

    fn load(&self, hash: &[u8]) -> Option<DepStatic> {
        let db = self.db?;
        let handle = db.cf_handle(self.static_cf)?;
        let bytes = db.get_cf(&handle, hash).ok().flatten()?;
        match decode_static(&bytes)? {
            StaticMeta::Block {
                height, min_height, ..
            } => Some(DepStatic::Block { height, min_height }),
            StaticMeta::Tx {
                min_height,
                closest_ancestor_block,
            } => Some(DepStatic::Tx {
                min_height,
                closest_ancestor_block,
            }),
        }
    }

    /// The height of the block `hash`, when it resolves to a block record.
    fn block_height(&mut self, hash: &[u8]) -> Option<u64> {
        match self.get(hash)? {
            DepStatic::Block { height, .. } => Some(*height),
            DepStatic::Tx { .. } => None,
        }
    }
}

/// Port of `TransactionStaticMetadata.create`: `min_height` is the max of the inherited
/// min-heights (parents + inputs) and the reward-lock heights of any spent block
/// (`height + reward_spend_min_blocks + 1`); `closest_ancestor_block` is the strictly
/// highest candidate block over the dependencies (a dep block itself, or a dep tx's
/// closest ancestor).
///
/// Returns `None` (Python fallback) when any dependency's static record is unresolvable —
/// or when two *distinct* candidate blocks tie at the maximum height: Python iterates a
/// `set` there, so the tie-breaking is its iteration order, which cannot be reproduced.
fn compute_tx_static(
    parsed: &Parsed,
    resolver: &mut StaticResolver<'_>,
    reward_spend_min_blocks: u64,
) -> Option<(u64, Vec<u8>)> {
    let mut min_height: u64 = 0;
    // candidate for closest ancestor: (block hash, height); ambiguous tie -> fallback
    let mut best: Option<(Vec<u8>, u64)> = None;
    let mut ambiguous = false;

    let parents = parsed.parents.iter();
    let inputs = parsed.inputs.iter().map(|(tx_id, _, _)| tx_id);
    let mut seen: Vec<&[u8]> = Vec::with_capacity(parsed.parents.len() + parsed.inputs.len());
    for dep_hash in parents.chain(inputs) {
        let is_input = seen.len() >= parsed.parents.len();
        let first_visit = !seen.contains(&dep_hash.as_slice());
        seen.push(dep_hash);

        let candidate: (Vec<u8>, u64) = match resolver.get(dep_hash)? {
            DepStatic::Block {
                height,
                min_height: dep_min,
            } => {
                let (height, dep_min) = (*height, *dep_min);
                min_height = min_height.max(dep_min);
                if is_input {
                    // spending a block reward locks the tx until the reward matures
                    min_height = min_height.max(height + reward_spend_min_blocks + 1);
                }
                (dep_hash.clone(), height)
            }
            DepStatic::Tx {
                min_height: dep_min,
                closest_ancestor_block,
            } => {
                let (dep_min, closest) = (*dep_min, closest_ancestor_block.clone());
                min_height = min_height.max(dep_min);
                let height = resolver.block_height(&closest)?;
                (closest, height)
            }
        };

        // Python's candidate set is deduplicated (get_all_dependencies is a set), so a dep
        // appearing as both parent and input contributes one candidate.
        if !first_visit {
            continue;
        }
        match &best {
            None => best = Some(candidate),
            Some((best_hash, best_height)) => {
                if candidate.1 > *best_height {
                    best = Some(candidate);
                    ambiguous = false;
                } else if candidate.1 == *best_height && candidate.0 != *best_hash {
                    // distinct blocks tied at the max: Python's set-iteration order decides
                    ambiguous = true;
                }
            }
        }
    }

    if ambiguous {
        return None;
    }
    let (closest, _) = best?;
    Some((min_height, closest))
}

/// Parse a batch of serialized vertices and run every Rust-side verification, end to end in
/// one GIL-released call: the stateless checks (always, per the canonical per-kind order),
/// and — when `include_scripts` is set — input-sigops counting and full script evaluation,
/// with spent txs resolved from the batch itself, `supplied_deps`, or a native RocksDB read
/// of `tx_cf`. Returns one [`TxOutcome`] per item plus the dep hashes fetched from RocksDB.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn verify_tx_from_bytes(
    py: Python<'_>,
    items: Vec<Vec<u8>>,
    supplied_deps: Vec<Vec<u8>>,
    db: Option<PyRef<'_, RocksDb>>,
    tx_cf: String,
    static_cf: String,
    include_scripts: bool,
    opcodes_version: u8,
    reward_spend_min_blocks: u64,
    max_size: usize,
    max_num_inputs: u64,
    block_data_max_size: u64,
    max_num_outputs: u64,
    max_output_script_size: u64,
    max_tx_sigops_output: u64,
    max_multisig_pubkeys: u64,
    max_multisig_signatures: i64,
    enable_checkdatasig_count: bool,
    p2pkh_version_byte: Vec<u8>,
    num_workers: usize,
) -> PyResult<(Vec<TxOutcome>, Vec<Vec<u8>>)> {
    let version = match opcodes_version {
        1 => OpcodesVersion::V1,
        2 => OpcodesVersion::V2,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown opcodes_version: {other}"
            )));
        }
    };
    let settings = StatelessSettings {
        max_num_inputs,
        block_data_max_size,
        max_num_outputs,
        max_output_script_size,
        max_tx_sigops_output,
        max_multisig_pubkeys,
        enable_checkdatasig_count,
    };
    let config = ScriptConfig {
        max_multisig_pubkeys: max_multisig_pubkeys as i64,
        max_multisig_signatures,
        p2pkh_version_byte,
    };
    // The native handle is cloned out while attached (PyRef is not Send); the Arc is.
    let native = db.as_ref().and_then(|d| d.native());

    let result = py.detach(|| {
        let pool = script::thread_pool(num_workers);
        pool.install(|| {
            let parse_bounded = |data: &Vec<u8>| {
                if data.len() > max_size {
                    return None;
                }
                parse(data)
            };
            let parsed_txs: Vec<Option<Parsed>> = items.par_iter().map(parse_bounded).collect();
            let supplied: Vec<Option<Parsed>> =
                supplied_deps.par_iter().map(parse_bounded).collect();

            // Stateless checks: dependency-free, computed for every parseable vertex.
            let stateless: Vec<Option<Vec<RawResult>>> = parsed_txs
                .par_iter()
                .map(|parsed| {
                    parsed.as_ref().map(|p| {
                        let checks = if p.version == VERSION_REGULAR_BLOCK {
                            BLOCK_CHECKS
                        } else {
                            TX_CHECKS
                        };
                        run_checks(checks, &VertexCheckData::from_parsed(p, &settings))
                    })
                })
                .collect();

            let (deps, fetched_hashes) = if include_scripts {
                resolve_deps(&parsed_txs, &supplied, native.as_ref(), &tx_cf)
            } else {
                (HashMap::new(), vec![])
            };

            // Static metadata is computed in batch order so spend chains resolve against
            // the in-batch results of their predecessors. Blocks are skipped (their static
            // metadata needs feature-activation walks; Python computes it).
            let mut static_resolver = StaticResolver {
                in_batch: HashMap::new(),
                fetched: HashMap::new(),
                db: native.as_ref(),
                static_cf: &static_cf,
            };
            let mut statics: Vec<Option<(u64, Vec<u8>)>> = Vec::with_capacity(items.len());
            for parsed in &parsed_txs {
                let computed = match parsed {
                    Some(p) if include_scripts && p.version != VERSION_REGULAR_BLOCK => {
                        compute_tx_static(p, &mut static_resolver, reward_spend_min_blocks)
                    }
                    _ => None,
                };
                if let (Some(p), Some((min_height, closest))) = (parsed, &computed) {
                    static_resolver.in_batch.insert(
                        p.hash.clone(),
                        DepStatic::Tx {
                            min_height: *min_height,
                            closest_ancestor_block: closest.clone(),
                        },
                    );
                }
                statics.push(computed);
            }

            // Build jobs + sigops per tx, then flatten the script jobs for evaluation:
            // single-input txs dominate, so load-balancing across all inputs of all txs
            // beats parallelizing per tx.
            let mut outcomes: Vec<TxOutcome> = Vec::with_capacity(items.len());
            let mut flat: Vec<(usize, ScriptJob)> = Vec::new();
            for (tx_index, (data, parsed)) in items.iter().zip(parsed_txs.iter()).enumerate() {
                let static_meta = statics[tx_index].take();
                let Some(parsed) = parsed else {
                    outcomes.push((STATUS_PARSE_FAILED, vec![], vec![], vec![], vec![], None));
                    continue;
                };
                let checks = stateless[tx_index]
                    .clone()
                    .expect("stateless results exist for every parsed vertex");
                let is_tx_with_inputs =
                    parsed.version != VERSION_REGULAR_BLOCK && !parsed.inputs.is_empty();
                if !include_scripts || !is_tx_with_inputs {
                    outcomes.push((
                        STATUS_EVALUATED,
                        checks,
                        vec![],
                        vec![],
                        vec![],
                        static_meta,
                    ));
                    continue;
                }
                match build_dep_stage(data, parsed, &deps, version, &settings) {
                    Ok(stage) => {
                        outcomes.push((
                            STATUS_EVALUATED,
                            checks,
                            stage.sigops,
                            vec![],
                            vec![],
                            static_meta,
                        ));
                        for job in stage.jobs {
                            flat.push((tx_index, job));
                        }
                    }
                    Err(missing) => {
                        outcomes.push((
                            STATUS_UNRESOLVED,
                            checks,
                            vec![],
                            vec![],
                            missing,
                            static_meta,
                        ));
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
                outcomes[tx_index].3.push(result);
            }
            (outcomes, fetched_hashes)
        })
    });
    Ok(result)
}

#[cfg(test)]
mod tests;
