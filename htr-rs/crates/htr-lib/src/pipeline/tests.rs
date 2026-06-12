//! Structural tests for the fused batch verification pipeline: parsing, stateless results,
//! sigops counting, tiered dependency resolution (in-batch, supplied, native RocksDB) and
//! outcome statuses. Check/script-evaluation *correctness* is covered by the dedicated
//! differential suites; these tests use trivially valid (`OP_1`) and invalid (`0x00`)
//! scripts to steer outcomes.

use pyo3::prelude::*;

use super::*;
use crate::storage::RocksDbWriteBatch;

/// Serialized regular tx: one input spending `dep_hash[index]` with `input_data`, one OP_1
/// output, fixed graph fields.
fn tx_bytes(dep_hash: &[u8], index: u8, input_data: &[u8]) -> Vec<u8> {
    let mut d = vec![0x00, 0x01, 0x00, 0x01, 0x01]; // sb, version, tokens, inputs, outputs
    d.extend_from_slice(dep_hash);
    d.push(index);
    d.extend_from_slice(&(input_data.len() as u16).to_be_bytes());
    d.extend_from_slice(input_data);
    d.extend_from_slice(&100i32.to_be_bytes()); // output value
    d.push(0x00); // token_data
    d.extend_from_slice(&[0x00, 0x01, 0x51]); // script: OP_1
    d.extend_from_slice(&10.5f64.to_be_bytes());
    d.extend_from_slice(&2000u32.to_be_bytes());
    d.push(0x00); // no parents
    d.extend_from_slice(&7u32.to_be_bytes());
    d
}

/// Serialized dependency tx: no inputs, `scripts.len()` outputs with the given scripts.
fn dep_bytes(scripts: &[&[u8]]) -> Vec<u8> {
    let mut d = vec![0x00, 0x01, 0x00, 0x00]; // sb, version, tokens, inputs=0
    d.push(scripts.len() as u8);
    for script in scripts {
        d.extend_from_slice(&100i32.to_be_bytes());
        d.push(0x00);
        d.extend_from_slice(&(script.len() as u16).to_be_bytes());
        d.extend_from_slice(script);
    }
    d.extend_from_slice(&1.0f64.to_be_bytes());
    d.extend_from_slice(&1000u32.to_be_bytes());
    d.push(0x00);
    d.extend_from_slice(&1u32.to_be_bytes());
    d
}

fn hash_of(data: &[u8]) -> Vec<u8> {
    parse(data).unwrap().hash
}

fn run(
    py: Python<'_>,
    items: Vec<Vec<u8>>,
    supplied: Vec<Vec<u8>>,
    db: Option<PyRef<'_, RocksDb>>,
    include_scripts: bool,
) -> (Vec<TxOutcome>, Vec<Vec<u8>>) {
    verify_tx_from_bytes(
        py,
        items,
        supplied,
        db,
        "tx".to_string(),
        include_scripts,
        2,          // opcodes_version V2
        100_000,    // max_size
        255,        // max_num_inputs
        100,        // block_data_max_size
        255,        // max_num_outputs
        1024,       // max_output_script_size
        1275,       // max_tx_sigops_output
        20,         // max_multisig_pubkeys
        15,         // max_multisig_signatures
        true,       // enable_checkdatasig_count
        vec![0x28], // p2pkh version byte
        2,          // num_workers
    )
    .unwrap()
}

#[test]
fn test_in_batch_dep_valid_and_invalid_scripts() {
    Python::initialize();
    Python::attach(|py| {
        let dep = dep_bytes(&[&[0x51], &[0x00]]); // output 0: OP_1 (valid); output 1: invalid opcode
        let dep_hash = hash_of(&dep);
        let valid_tx = tx_bytes(&dep_hash, 0, b"");
        let invalid_tx = tx_bytes(&dep_hash, 1, b"");
        let (outcomes, fetched) = run(
            py,
            vec![valid_tx, invalid_tx, dep.clone()],
            vec![],
            None,
            true,
        );
        assert!(fetched.is_empty());

        assert_eq!(outcomes[0].0, STATUS_EVALUATED);
        // tx stateless results: one entry per TX_CHECKS, all passing
        assert_eq!(outcomes[0].1, vec![None; TX_CHECKS.len()]);
        // one sigops entry per input: empty input data counts zero sigops
        assert_eq!(outcomes[0].2, vec![(None, 0)]);
        assert_eq!(outcomes[0].3, vec![None]);

        assert_eq!(outcomes[1].0, STATUS_EVALUATED);
        let (kind, _) = outcomes[1].3[0].clone().unwrap();
        assert_eq!(kind, "InvalidScriptError");

        // the dep itself has no inputs: stateless still computed, no sigops/script results
        assert_eq!(outcomes[2].0, STATUS_EVALUATED);
        // TooFewInputs is expected: a 0-input tx fails CHECK_NUMBER_OF_INPUTS
        let (kind, _) = outcomes[2].1[0].clone().unwrap();
        assert_eq!(kind, "TooFewInputs");
        assert_eq!(outcomes[2].2, vec![]);
        assert_eq!(outcomes[2].3, vec![]);
    });
}

#[test]
fn test_stateless_only_mode_skips_dep_resolution() {
    Python::initialize();
    Python::attach(|py| {
        // the dep is missing, but include_scripts=false never resolves deps
        let tx = tx_bytes(&[0xEE; 32], 0, b"");
        let (outcomes, fetched) = run(py, vec![tx], vec![], None, false);
        assert!(fetched.is_empty());
        assert_eq!(outcomes[0].0, STATUS_EVALUATED);
        assert_eq!(outcomes[0].1, vec![None; TX_CHECKS.len()]);
        assert_eq!(outcomes[0].2, vec![]);
        assert_eq!(outcomes[0].3, vec![]);
    });
}

#[test]
fn test_block_gets_block_checks_and_no_scripts() {
    Python::initialize();
    Python::attach(|py| {
        let mut d = vec![0x00, 0x00, 0x01]; // sb, version=block, outputs=1
        d.extend_from_slice(&6400i32.to_be_bytes());
        d.push(0x00);
        d.extend_from_slice(&[0x00, 0x01, 0x51]);
        d.extend_from_slice(&21.0f64.to_be_bytes());
        d.extend_from_slice(&2000u32.to_be_bytes());
        d.push(0x00); // no parents
        d.push(0x00); // no block data
        d.extend_from_slice(&[0x00; 16]); // 16-byte nonce
        let (outcomes, _) = run(py, vec![d], vec![], None, true);
        assert_eq!(outcomes[0].0, STATUS_EVALUATED);
        assert_eq!(outcomes[0].1, vec![None; BLOCK_CHECKS.len()]);
        assert_eq!(outcomes[0].2, vec![]);
        assert_eq!(outcomes[0].3, vec![]);
    });
}

#[test]
fn test_missing_dep_keeps_stateless_results() {
    Python::initialize();
    Python::attach(|py| {
        let tx = tx_bytes(&[0xEE; 32], 0, b"");
        let (outcomes, _) = run(py, vec![tx], vec![], None, true);
        assert_eq!(outcomes[0].0, STATUS_UNRESOLVED);
        assert_eq!(outcomes[0].1, vec![None; TX_CHECKS.len()]);
        assert_eq!(outcomes[0].4, vec![vec![0xEE; 32]]);
    });
}

#[test]
fn test_supplied_dep_resolves() {
    Python::initialize();
    Python::attach(|py| {
        let dep = dep_bytes(&[&[0x51]]);
        let tx = tx_bytes(&hash_of(&dep), 0, b"");
        let (outcomes, _) = run(py, vec![tx], vec![dep], None, true);
        assert_eq!(outcomes[0].0, STATUS_EVALUATED);
        assert_eq!(outcomes[0].3, vec![None]);
    });
}

#[test]
fn test_db_resolved_dep_reports_fetched_hash() {
    Python::initialize();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db").to_str().unwrap().to_string();
    Python::attach(|py| {
        let db = Py::new(py, RocksDb::new(py, path, None).unwrap()).unwrap();
        db.borrow(py).create_cf(py, "tx").unwrap();
        let dep = dep_bytes(&[&[0x51]]);
        let dep_hash = hash_of(&dep);
        let batch = RocksDbWriteBatch::new();
        batch.put("tx", dep_hash.clone(), dep).unwrap();
        db.borrow(py).write(py, &batch).unwrap();

        let tx = tx_bytes(&dep_hash, 0, b"");
        let (outcomes, fetched) = run(py, vec![tx], vec![], Some(db.borrow(py)), true);
        assert_eq!(outcomes[0].0, STATUS_EVALUATED);
        assert_eq!(outcomes[0].3, vec![None]);
        // the natively-fetched dep is reported for Python-side cache warming
        assert_eq!(fetched, vec![dep_hash]);
    });
}

#[test]
fn test_unparseable_tx_reports_parse_failed() {
    Python::initialize();
    Python::attach(|py| {
        let (outcomes, _) = run(py, vec![vec![0x00, 0xFF, 0x01]], vec![], None, true);
        assert_eq!(outcomes[0].0, STATUS_PARSE_FAILED);
        assert_eq!(outcomes[0].1, vec![]);
    });
}

#[test]
fn test_out_of_range_spent_index_unresolved_with_no_missing() {
    Python::initialize();
    Python::attach(|py| {
        let dep = dep_bytes(&[&[0x51]]);
        let tx = tx_bytes(&hash_of(&dep), 7, b""); // dep has only output 0
        let (outcomes, _) = run(py, vec![tx, dep], vec![], None, true);
        assert_eq!(outcomes[0].0, STATUS_UNRESOLVED);
        assert_eq!(outcomes[0].4, Vec::<Vec<u8>>::new());
    });
}

#[test]
fn test_sigops_counted_per_input() {
    Python::initialize();
    Python::attach(|py| {
        // input 0: empty data (0 sigops); input 1: OP_16 OP_CHECKMULTISIG in input data
        // against a non-multisig output script -> the input data itself is counted (16)
        let dep = dep_bytes(&[&[0x51], &[0x51]]);
        let dep_hash = hash_of(&dep);
        let mut d = vec![0x00, 0x01, 0x00, 0x02, 0x01]; // 2 inputs
        d.extend_from_slice(&dep_hash);
        d.push(0x00);
        d.extend_from_slice(&[0x00, 0x00]);
        d.extend_from_slice(&dep_hash);
        d.push(0x01);
        d.extend_from_slice(&[0x00, 0x02, 0x60, 0xAE]); // OP_16 OP_CHECKMULTISIG
        d.extend_from_slice(&100i32.to_be_bytes());
        d.push(0x00);
        d.extend_from_slice(&[0x00, 0x01, 0x51]);
        d.extend_from_slice(&10.5f64.to_be_bytes());
        d.extend_from_slice(&2000u32.to_be_bytes());
        d.push(0x00);
        d.extend_from_slice(&7u32.to_be_bytes());

        let (outcomes, _) = run(py, vec![d, dep], vec![], None, true);
        assert_eq!(outcomes[0].0, STATUS_EVALUATED);
        assert_eq!(outcomes[0].2[0], (None, 0));
        assert_eq!(outcomes[0].2[1], (None, 16));
    });
}

#[test]
fn test_multi_input_results_in_input_order() {
    Python::initialize();
    Python::attach(|py| {
        // input 0 spends the invalid-script output, input 1 the valid one
        let dep = dep_bytes(&[&[0x00], &[0x51]]);
        let dep_hash = hash_of(&dep);
        let mut d = vec![0x00, 0x01, 0x00, 0x02, 0x01]; // 2 inputs
        for index in [0u8, 1u8] {
            d.extend_from_slice(&dep_hash);
            d.push(index);
            d.extend_from_slice(&[0x00, 0x00]);
        }
        d.extend_from_slice(&100i32.to_be_bytes());
        d.push(0x00);
        d.extend_from_slice(&[0x00, 0x01, 0x51]);
        d.extend_from_slice(&10.5f64.to_be_bytes());
        d.extend_from_slice(&2000u32.to_be_bytes());
        d.push(0x00);
        d.extend_from_slice(&7u32.to_be_bytes());

        let (outcomes, _) = run(py, vec![d, dep], vec![], None, true);
        assert_eq!(outcomes[0].0, STATUS_EVALUATED);
        assert_eq!(outcomes[0].3.len(), 2);
        let (kind, _) = outcomes[0].3[0].clone().unwrap();
        assert_eq!(kind, "InvalidScriptError");
        assert_eq!(outcomes[0].3[1], None);
    });
}
