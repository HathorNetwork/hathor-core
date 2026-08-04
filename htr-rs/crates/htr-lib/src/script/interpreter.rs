//! The stack machine: faithful ports of `execute_eval`/`raw_script_eval` from
//! `hathor/transaction/scripts/execute.py`, the opcode functions from `opcode.py`, and the
//! multisig input handling from `multi_sig.py`.

use std::collections::HashMap;

use crate::script::crypto::{self, SigCheck};
use crate::script::opcodes::{self, get_data_value, get_script_op};
use crate::script::{ErrorKind, EvalError, OpcodesVersion, ScriptConfig, ScriptJob, matchers};

/// A stack item: Python's stack holds `bytes` or `int` (ints come from `OP_0..OP_16` and the
/// literal `0`/`1` pushed by comparison/signature opcodes). Where Python distinguishes the two
/// (asserts, `isinstance` checks), the distinction is consensus-visible and preserved here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackItem {
    Bytes(Vec<u8>),
    Int(i64),
}

/// Per-job data the opcodes read (the Rust analogue of `DetachedUtxoScriptExtras`).
pub struct EvalContext<'a> {
    pub version: OpcodesVersion,
    pub sighash_all_data: &'a [u8],
    pub timestamp: i64,
    pub spent_output_value: u64,
    pub tx_outputs: &'a [(u64, Vec<u8>)],
    pub config: &'a ScriptConfig,
}

type Stack = Vec<StackItem>;

fn assertion_error(message: &str) -> EvalError {
    EvalError::new(ErrorKind::AssertionFailed, message)
}

/// Pop the top item, which Python `assert`s to be `bytes`.
fn pop_bytes(stack: &mut Stack, op_name: &str) -> Result<Vec<u8>, EvalError> {
    match stack.pop() {
        Some(StackItem::Bytes(bytes)) => Ok(bytes),
        Some(StackItem::Int(_)) => Err(assertion_error(op_name)),
        None => Err(assertion_error(op_name)),
    }
}

/// `evaluate_final_stack`: valid iff exactly one item is left and it is the integer 1.
pub fn evaluate_final_stack(stack: &mut Stack) -> Result<(), EvalError> {
    if stack.is_empty() {
        return Err(EvalError::new(
            ErrorKind::FinalStackInvalid,
            "Empty Stack left",
        ));
    }
    if stack.len() > 1 {
        let message = "Stack left with more than one value";
        return Err(EvalError::new(ErrorKind::FinalStackInvalid, message));
    }
    match stack.pop() {
        Some(StackItem::Int(1)) => Ok(()),
        _ => Err(EvalError::new(
            ErrorKind::FinalStackInvalid,
            "Stack left with False value",
        )),
    }
}

/// `execute_eval`: run the opcode stream over a fresh stack, then check the final stack.
pub fn execute_eval(data: &[u8], ctx: &EvalContext<'_>) -> Result<(), EvalError> {
    let mut stack: Stack = Vec::new();
    let data_len = data.len();
    let mut pos = 0;
    while pos < data_len {
        let (opcode, new_pos) = get_script_op(pos, data, Some(&mut stack))?;
        pos = new_pos;
        if opcodes::is_pushdata(opcode) {
            continue;
        }
        execute_op_code(opcode, &mut stack, ctx)?;
    }
    evaluate_final_stack(&mut stack)
}

/// `execute_op_code`: dispatch a function opcode, with the V1-only opcodes gated exactly like
/// the Python dispatch table (under V2 they are valid opcodes that miss the table, so the
/// failure is a plain `ScriptError`, not an `InvalidScriptError`).
fn execute_op_code(opcode: u8, stack: &mut Stack, ctx: &EvalContext<'_>) -> Result<(), EvalError> {
    let v1 = ctx.version == OpcodesVersion::V1;
    match opcode {
        opcodes::OP_DUP => op_dup(stack),
        opcodes::OP_EQUAL => op_equal(stack),
        opcodes::OP_EQUALVERIFY => op_equalverify(stack),
        opcodes::OP_CHECKSIG => op_checksig(stack, ctx),
        opcodes::OP_HASH160 => op_hash160(stack),
        opcodes::OP_GREATERTHAN_TIMESTAMP => op_greaterthan_timestamp(stack, ctx),
        opcodes::OP_CHECKMULTISIG => op_checkmultisig(stack, ctx),
        opcodes::OP_DATA_STREQUAL if v1 => op_data_strequal(stack),
        opcodes::OP_DATA_GREATERTHAN if v1 => op_data_greaterthan(stack),
        opcodes::OP_DATA_MATCH_VALUE if v1 => op_data_match_value(stack),
        opcodes::OP_CHECKDATASIG if v1 => op_checkdatasig(stack),
        opcodes::OP_FIND_P2PKH if v1 => op_find_p2pkh(stack, ctx),
        _ => Err(EvalError::new(
            ErrorKind::Script,
            format!("unknown opcode: {opcode}"),
        )),
    }
}

/// `MultiSig.get_multisig_redeem_script_pos`: position of the last opcode in `input_data`,
/// found with a *validating* walk (invalid opcodes and truncated pushes raise here).
pub fn get_multisig_redeem_script_pos(input_data: &[u8]) -> Result<usize, EvalError> {
    let mut pos = 0;
    let mut last_pos = 0;
    let data_len = input_data.len();
    while pos < data_len {
        last_pos = pos;
        let (_, new_pos) = get_script_op(pos, input_data, None)?;
        pos = new_pos;
    }
    Ok(last_pos)
}

/// `MultiSig.get_multisig_data`: signatures plus the redeem script stripped of its push
/// framing. This walk is *lax*: only bytes 1..=75 and `OP_PUSHDATA1` are parsed as pushes
/// (still validated, so truncated pushes raise `OutOfData`); every other byte — including
/// invalid opcodes — just advances by one and pushes nothing.
pub fn get_multisig_data(input_data: &[u8]) -> Result<Vec<u8>, EvalError> {
    let mut pos = 0;
    let mut last_pos = 0;
    let mut stack: Stack = Vec::new();
    let data_len = input_data.len();
    while pos < data_len {
        last_pos = pos;
        let opcode = input_data[pos];
        if (1..=75).contains(&opcode) || opcode == opcodes::OP_PUSHDATA1 {
            let (_, new_pos) = get_script_op(pos, input_data, Some(&mut stack))?;
            pos = new_pos;
        } else {
            pos += 1;
        }
    }

    // Python does `stack[-1]` (IndexError on empty); the lax walk above only pushes bytes.
    let Some(last) = stack.last() else {
        return Err(EvalError::new(
            ErrorKind::IndexError,
            "list index out of range",
        ));
    };
    let StackItem::Bytes(redeem_script) = last else {
        return Err(assertion_error(
            "get_multisig_data: redeem script is not bytes",
        ));
    };
    let mut result = Vec::with_capacity(last_pos + redeem_script.len());
    result.extend_from_slice(&input_data[..last_pos]);
    result.extend_from_slice(redeem_script);
    Ok(result)
}

/// `raw_script_eval`: single-pass eval of `input_data + output_script`, except for MultiSig
/// output scripts which take the two-pass path (redeem-script hash check, then signatures
/// against the unwrapped redeem script).
pub fn raw_script_eval(
    input_data: &[u8],
    output_script: &[u8],
    ctx: &EvalContext<'_>,
) -> Result<(), EvalError> {
    if matchers::is_multisig_script(output_script) {
        let redeem_script_pos = get_multisig_redeem_script_pos(input_data)?;
        let tail = &input_data[redeem_script_pos..];
        let mut full_data = Vec::with_capacity(tail.len() + output_script.len());
        full_data.extend_from_slice(tail);
        full_data.extend_from_slice(output_script);
        execute_eval(&full_data, ctx)?;

        let multisig_data = get_multisig_data(input_data)?;
        execute_eval(&multisig_data, ctx)
    } else {
        let mut full_data = Vec::with_capacity(input_data.len() + output_script.len());
        full_data.extend_from_slice(input_data);
        full_data.extend_from_slice(output_script);
        execute_eval(&full_data, ctx)
    }
}

/// Evaluate one job: the Rust analogue of `execute_script_verification_job`.
pub fn eval_job(
    job: &ScriptJob,
    version: OpcodesVersion,
    config: &ScriptConfig,
) -> Result<(), EvalError> {
    let ctx = EvalContext {
        version,
        sighash_all_data: &job.sighash_all_data,
        timestamp: job.tx_timestamp,
        spent_output_value: job.spent_output_value,
        tx_outputs: &job.tx_outputs,
        config,
    };
    raw_script_eval(&job.input_data, &job.output_script, &ctx)
}

fn op_dup(stack: &mut Stack) -> Result<(), EvalError> {
    let Some(top) = stack.last() else {
        return Err(EvalError::new(
            ErrorKind::MissingStackItems,
            "OP_DUP: empty stack",
        ));
    };
    let duplicated = top.clone();
    stack.push(duplicated);
    Ok(())
}

fn op_greaterthan_timestamp(stack: &mut Stack, ctx: &EvalContext<'_>) -> Result<(), EvalError> {
    if stack.is_empty() {
        let message = "OP_GREATERTHAN_TIMESTAMP: empty stack";
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }
    let buf = pop_bytes(stack, "OP_GREATERTHAN_TIMESTAMP: timelock is not bytes")?;
    // Python: struct.unpack('!I', buf) requires exactly 4 bytes, else struct.error.
    let Ok(array) = <[u8; 4]>::try_from(buf.as_slice()) else {
        let message = "unpack requires a buffer of 4 bytes";
        return Err(EvalError::new(ErrorKind::StructError, message));
    };
    let timelock = u32::from_be_bytes(array);
    if ctx.timestamp <= i64::from(timelock) {
        let message = format!("The output is locked until {timelock}");
        return Err(EvalError::new(ErrorKind::TimeLocked, message));
    }
    Ok(())
}

fn op_equalverify(stack: &mut Stack) -> Result<(), EvalError> {
    if stack.len() < 2 {
        let message = format!(
            "OP_EQUALVERIFY: need 2 elements on stack, currently {}",
            stack.len()
        );
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }
    op_equal(stack)?;
    let is_equal = stack.pop().expect("op_equal always pushes its result");
    if is_equal == StackItem::Int(0) {
        let message = "Failed to verify if elements are equal";
        return Err(EvalError::new(ErrorKind::EqualVerifyFailed, message));
    }
    Ok(())
}

fn op_equal(stack: &mut Stack) -> Result<(), EvalError> {
    if stack.len() < 2 {
        let message = format!(
            "OP_EQUAL: need 2 elements on stack, currently {}",
            stack.len()
        );
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }
    let elem1 = pop_bytes(stack, "OP_EQUAL: element is not bytes")?;
    let elem2 = pop_bytes(stack, "OP_EQUAL: element is not bytes")?;
    if elem1 == elem2 {
        stack.push(StackItem::Int(1));
    } else {
        stack.push(StackItem::Int(0));
    }
    Ok(())
}

fn op_checksig(stack: &mut Stack, ctx: &EvalContext<'_>) -> Result<(), EvalError> {
    if stack.len() < 2 {
        let message = format!(
            "OP_CHECKSIG: need 2 elements on stack, currently {}",
            stack.len()
        );
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }
    let pubkey = pop_bytes(stack, "OP_CHECKSIG: pubkey is not bytes")?;
    let signature = pop_bytes(stack, "OP_CHECKSIG: signature is not bytes")?;
    match crypto::checksig(&pubkey, &signature, ctx.sighash_all_data, "OP_CHECKSIG")? {
        SigCheck::Valid => stack.push(StackItem::Int(1)),
        SigCheck::Invalid => stack.push(StackItem::Int(0)),
    }
    Ok(())
}

fn op_hash160(stack: &mut Stack) -> Result<(), EvalError> {
    if stack.is_empty() {
        return Err(EvalError::new(
            ErrorKind::MissingStackItems,
            "OP_HASH160: empty stack",
        ));
    }
    let elem = pop_bytes(stack, "OP_HASH160: element is not bytes")?;
    stack.push(StackItem::Bytes(crypto::hash160(&elem).to_vec()));
    Ok(())
}

fn op_checkdatasig(stack: &mut Stack) -> Result<(), EvalError> {
    if stack.len() < 3 {
        let message = format!(
            "OP_CHECKDATASIG: need 3 elements on stack, currently {}",
            stack.len()
        );
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }
    let pubkey = pop_bytes(stack, "OP_CHECKDATASIG: pubkey is not bytes")?;
    let signature = pop_bytes(stack, "OP_CHECKDATASIG: signature is not bytes")?;
    let data = pop_bytes(stack, "OP_CHECKDATASIG: data is not bytes")?;
    match crypto::checksig(&pubkey, &signature, &data, "OP_CHECKDATASIG")? {
        SigCheck::Valid => {
            stack.push(StackItem::Bytes(data));
            Ok(())
        }
        SigCheck::Invalid => Err(EvalError::new(ErrorKind::OracleChecksigFailed, "")),
    }
}

fn op_data_strequal(stack: &mut Stack) -> Result<(), EvalError> {
    if stack.len() < 3 {
        let message = format!(
            "OP_DATA_STREQUAL: need 3 elements on stack, currently {}",
            stack.len()
        );
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }
    let value = pop_bytes(stack, "OP_DATA_STREQUAL: value is not bytes")?;
    let data_k = stack.pop().expect("stack has at least 3 items");
    let data = pop_bytes(stack, "OP_DATA_STREQUAL: data is not bytes")?;

    let StackItem::Int(k) = data_k else {
        let message = "OP_DATA_STREQUAL: value on stack should be an integer";
        return Err(EvalError::new(ErrorKind::VerifyFailed, message));
    };

    let data_value = get_data_value(k, &data)?;
    if data_value != value.as_slice() {
        // Python formats the error message with `.decode('utf-8')` on both values, so a
        // mismatch with non-UTF-8 data raises UnicodeDecodeError instead of VerifyFailed.
        if std::str::from_utf8(data_value).is_err() || std::str::from_utf8(&value).is_err() {
            let message = "invalid utf-8 in OP_DATA_STREQUAL message formatting";
            return Err(EvalError::new(ErrorKind::UnicodeDecode, message));
        }
        return Err(EvalError::new(
            ErrorKind::VerifyFailed,
            "OP_DATA_STREQUAL: mismatch",
        ));
    }

    stack.push(StackItem::Bytes(data));
    Ok(())
}

fn op_data_greaterthan(stack: &mut Stack) -> Result<(), EvalError> {
    if stack.len() < 3 {
        let message = format!(
            "OP_DATA_GREATERTHAN: need 3 elements on stack, currently {}",
            stack.len()
        );
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }
    let value = pop_bytes(stack, "OP_DATA_GREATERTHAN: value is not bytes")?;
    let data_k = stack.pop().expect("stack has at least 3 items");
    let data = pop_bytes(stack, "OP_DATA_GREATERTHAN: data is not bytes")?;

    let StackItem::Int(k) = data_k else {
        let message = "OP_DATA_STREQUAL: value on stack should be an integer";
        return Err(EvalError::new(ErrorKind::VerifyFailed, message));
    };

    let data_value = get_data_value(k, &data)?;
    // Python catches (ValueError, struct.error) from these two conversions -> VerifyFailed.
    let (Ok(data_int), Ok(value_int)) = (
        opcodes::binary_to_int(data_value),
        opcodes::binary_to_int(&value),
    ) else {
        return Err(EvalError::new(ErrorKind::VerifyFailed, ""));
    };

    if data_int <= value_int {
        let message = format!("op_data_greaterthan: {data_int} x {value_int}");
        return Err(EvalError::new(ErrorKind::VerifyFailed, message));
    }

    stack.push(StackItem::Bytes(data));
    Ok(())
}

fn op_data_match_value(stack: &mut Stack) -> Result<(), EvalError> {
    if stack.is_empty() {
        let message = "OP_DATA_MATCH_VALUE: empty stack";
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }
    let data_n_items = pop_bytes(stack, "OP_DATA_MATCH_VALUE: items count is not bytes")?;
    // Stack bytes are never empty (zero-length pushes are rejected), so indexing is safe;
    // the IndexError mapping is kept for strict parity with Python's `data_n_items[0]`.
    let Some(&n_items_byte) = data_n_items.first() else {
        return Err(EvalError::new(ErrorKind::IndexError, "index out of range"));
    };
    let n_items = n_items_byte as usize;

    // number of items in stack that will be used
    let will_use = 2 * n_items + 3; // n data_points, n + 1 keys, k and data
    if stack.len() < will_use {
        let message = format!(
            "OP_DATA_MATCH_VALUE: need {} elements on stack, currently {}",
            will_use,
            stack.len()
        );
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }

    let mut items: HashMap<u64, Vec<u8>> = HashMap::with_capacity(n_items);
    for _ in 0..n_items {
        let pubkey = pop_bytes(stack, "OP_DATA_MATCH_VALUE: pubkey is not bytes")?;
        let buf = pop_bytes(stack, "OP_DATA_MATCH_VALUE: value is not bytes")?;
        // Python catches (ValueError, struct.error) here -> VerifyFailed.
        let Ok(value) = opcodes::binary_to_int(&buf) else {
            return Err(EvalError::new(ErrorKind::VerifyFailed, ""));
        };
        items.insert(value, pubkey);
    }

    // one pubkey is left on stack; it is popped untyped in Python
    let last_pubkey = stack.pop().expect("stack size checked by will_use");
    let data_k = stack.pop().expect("stack size checked by will_use");
    let StackItem::Int(k) = data_k else {
        return Err(assertion_error(
            "OP_DATA_MATCH_VALUE: data index is not an integer",
        ));
    };
    let data = pop_bytes(stack, "OP_DATA_MATCH_VALUE: data is not bytes")?;

    let data_value = get_data_value(k, &data)?;
    // Unlike op_data_greaterthan, this conversion is OUTSIDE the try block in Python, so a
    // bad length is an uncaught struct.error rather than VerifyFailed.
    let data_int = opcodes::binary_to_int(data_value)?;

    let winner_pubkey = match items.remove(&data_int) {
        Some(pubkey) => StackItem::Bytes(pubkey),
        None => last_pubkey,
    };
    // Python asserts the winner is str/bytes; the untyped `last_pubkey` may be an int.
    let StackItem::Bytes(_) = winner_pubkey else {
        return Err(assertion_error(
            "OP_DATA_MATCH_VALUE: winner pubkey is not bytes",
        ));
    };
    stack.push(winner_pubkey);
    Ok(())
}

fn op_find_p2pkh(stack: &mut Stack, ctx: &EvalContext<'_>) -> Result<(), EvalError> {
    if stack.is_empty() {
        return Err(EvalError::new(
            ErrorKind::MissingStackItems,
            "OP_FIND_P2PKH: empty stack",
        ));
    }
    let contract_value = ctx.spent_output_value;

    let Some(StackItem::Bytes(address)) = stack.pop() else {
        return Err(EvalError::new(ErrorKind::VerifyFailed, ""));
    };

    // Python compares base58-encoded addresses; base58 is injective over bytes, so comparing
    // the raw 25-byte form (version byte + hash160 + 4-byte checksum) is equivalent.
    for (output_value, output_script) in ctx.tx_outputs {
        let Some(hash) = matchers::parse_p2pkh_hash160(output_script) else {
            continue;
        };
        let mut candidate = Vec::with_capacity(ctx.config.p2pkh_version_byte.len() + 24);
        candidate.extend_from_slice(&ctx.config.p2pkh_version_byte);
        candidate.extend_from_slice(&hash);
        let checksum = crypto::address_checksum(&candidate);
        candidate.extend_from_slice(&checksum);
        if candidate == address && *output_value == contract_value {
            stack.push(StackItem::Int(1));
            return Ok(());
        }
    }
    // didn't find any match
    Err(EvalError::new(ErrorKind::VerifyFailed, ""))
}

fn op_checkmultisig(stack: &mut Stack, ctx: &EvalContext<'_>) -> Result<(), EvalError> {
    if stack.is_empty() {
        let message = "OP_CHECKMULTISIG: empty stack";
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }

    // Pop the quantity of pubkeys
    let pubkey_count = match stack.pop().expect("stack is non-empty") {
        StackItem::Int(count) => count,
        StackItem::Bytes(_) => {
            let message = "OP_CHECKMULTISIG: pubkey count should be an integer";
            return Err(EvalError::new(ErrorKind::InvalidStackData, message));
        }
    };

    if pubkey_count > ctx.config.max_multisig_pubkeys {
        let message = format!(
            "OP_CHECKMULTISIG: pubkey count ({}) exceeded the limit ({})",
            pubkey_count, ctx.config.max_multisig_pubkeys
        );
        return Err(EvalError::new(ErrorKind::InvalidStackData, message));
    }

    // Stack integers are always 0..=16, but clamp like Python's `range(count)` would.
    let pubkey_count = usize::try_from(pubkey_count).unwrap_or(0);
    if stack.len() < pubkey_count {
        let message = "OP_CHECKMULTISIG: not enough public keys on the stack";
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }

    // Get all pubkeys (untyped in Python; a non-bytes item fails later inside checksig)
    let mut pubkeys: Vec<StackItem> = Vec::with_capacity(pubkey_count);
    for _ in 0..pubkey_count {
        pubkeys.push(stack.pop().expect("stack size checked above"));
    }

    if stack.is_empty() {
        let message = "OP_CHECKMULTISIG: less elements than should on the stack";
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }

    // Pop the quantity of signatures required
    let signatures_count = match stack.pop().expect("stack is non-empty") {
        StackItem::Int(count) => count,
        StackItem::Bytes(_) => {
            let message = "OP_CHECKMULTISIG: signatures count should be an integer";
            return Err(EvalError::new(ErrorKind::InvalidStackData, message));
        }
    };

    if signatures_count > ctx.config.max_multisig_signatures {
        let message = format!(
            "OP_CHECKMULTISIG: signature count ({}) exceeded the limit ({})",
            signatures_count, ctx.config.max_multisig_signatures
        );
        return Err(EvalError::new(ErrorKind::InvalidStackData, message));
    }

    let signatures_count = usize::try_from(signatures_count).unwrap_or(0);
    if stack.len() < signatures_count {
        let message = "OP_CHECKMULTISIG: not enough signatures on the stack";
        return Err(EvalError::new(ErrorKind::MissingStackItems, message));
    }

    // Get all signatures (untyped, like the pubkeys)
    let mut signatures: Vec<StackItem> = Vec::with_capacity(signatures_count);
    for _ in 0..signatures_count {
        signatures.push(stack.pop().expect("stack size checked above"));
    }

    // For each signature we check if it's valid with one of the public keys.
    // Signatures must be in order (same as the public keys in the multi sig wallet), so the
    // pubkey cursor only ever advances.
    let mut pubkey_index = 0;
    'signatures: for signature in &signatures {
        while pubkey_index < pubkeys.len() {
            let pubkey = &pubkeys[pubkey_index];
            pubkey_index += 1;
            if checksig_pair(signature, pubkey, ctx)? {
                continue 'signatures;
            }
        }
        // finished all pubkeys and did not verify all signatures
        stack.push(StackItem::Int(0));
        return Ok(());
    }

    // If all signatures are valid we push 1
    stack.push(StackItem::Int(1));
    Ok(())
}

/// The sub-`op_checksig` call `op_checkmultisig` makes per (signature, pubkey) pair: Python
/// builds a fresh two-item stack and runs `op_checksig` on it, so the assert-on-non-bytes and
/// pubkey `ScriptError` paths apply per pair.
fn checksig_pair(
    signature: &StackItem,
    pubkey: &StackItem,
    ctx: &EvalContext<'_>,
) -> Result<bool, EvalError> {
    let StackItem::Bytes(pubkey) = pubkey else {
        return Err(assertion_error("OP_CHECKSIG: pubkey is not bytes"));
    };
    let StackItem::Bytes(signature) = signature else {
        return Err(assertion_error("OP_CHECKSIG: signature is not bytes"));
    };
    let check = crypto::checksig(pubkey, signature, ctx.sighash_all_data, "OP_CHECKSIG")?;
    Ok(check == SigCheck::Valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // End-to-end vectors generated from the Python reference (`raw_script_eval` over
    // `DetachedUtxoScriptExtras`); the expected outcome is the Python exception class.
    const SIGHASH: &[u8] = b"sighash-all-data-test-vector";
    const P2PKH_IN: &str = "4630440220254b464e9a12961b43730e32415966c551eedc362bd65095d7f37ec3c601b55302201e83b83cf3a823a002c56801e22ed6b88a770bb74aa756806b43bb29107689e02102bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020d";
    const P2PKH_OUT: &str = "76a914a390bb4d6d4ab570767ef21f66c3edc1a4d6902688ac";
    const P2PKH_OUT_TIMELOCK: &str =
        "04000003e86f76a914a390bb4d6d4ab570767ef21f66c3edc1a4d6902688ac";
    const MS_IN: &str = "473045022048438d8b4ac2b1f11717cc008b1a4b088b195c40f308eba87cb8069e0f7161e6022100c9c8bff33ee66444844d48196b04d24a0331d19a9aed5c6e8340e73cedb05f1a463044022057108e5142276e9e7ff9b0c06921c7d023fac5cac70953012655894d6e4304cc02202c937a8ba274324c2407dfa972baab0aa6c0bcdbe0be46dd5e0840d51bc5858a4c695221034a5169f673aa632f538aaa128b6348536db2b637fd89073d49b6a23879cdb3ad21039d1abaec9f5715a15c7628244170951e0f85e87f68ca5393d3f9fc3fa23a69c8210370b55404702ffa86ecfa4e88e0f354004a0965a5eea5fbbd297436001ae920df53ae";
    const MS_IN_SWAPPED: &str = "463044022057108e5142276e9e7ff9b0c06921c7d023fac5cac70953012655894d6e4304cc02202c937a8ba274324c2407dfa972baab0aa6c0bcdbe0be46dd5e0840d51bc5858a473045022048438d8b4ac2b1f11717cc008b1a4b088b195c40f308eba87cb8069e0f7161e6022100c9c8bff33ee66444844d48196b04d24a0331d19a9aed5c6e8340e73cedb05f1a4c695221034a5169f673aa632f538aaa128b6348536db2b637fd89073d49b6a23879cdb3ad21039d1abaec9f5715a15c7628244170951e0f85e87f68ca5393d3f9fc3fa23a69c8210370b55404702ffa86ecfa4e88e0f354004a0965a5eea5fbbd297436001ae920df53ae";
    const MS_OUT: &str = "a914435d1cb21e38a88634dfe325e1ec0fd5c98adc4387";
    // Pushes the 25-byte address (version byte 0x28 + hash160 + checksum).
    const FIND_P2PKH_IN: &str = "1928a390bb4d6d4ab570767ef21f66c3edc1a4d69026d8ef8e36";

    fn config() -> ScriptConfig {
        ScriptConfig {
            max_multisig_pubkeys: 20,
            max_multisig_signatures: 15,
            p2pkh_version_byte: vec![0x28],
        }
    }

    struct Eval {
        version: OpcodesVersion,
        timestamp: i64,
        spent_output_value: u64,
        tx_outputs: Vec<(u64, Vec<u8>)>,
    }

    impl Default for Eval {
        fn default() -> Self {
            Self {
                version: OpcodesVersion::V2,
                timestamp: 2000,
                spent_output_value: 100,
                tx_outputs: vec![],
            }
        }
    }

    impl Eval {
        fn run(&self, input_data: &[u8], output_script: &[u8]) -> Result<(), ErrorKind> {
            let config = config();
            let ctx = EvalContext {
                version: self.version,
                sighash_all_data: SIGHASH,
                timestamp: self.timestamp,
                spent_output_value: self.spent_output_value,
                tx_outputs: &self.tx_outputs,
                config: &config,
            };
            raw_script_eval(input_data, output_script, &ctx).map_err(|e| e.kind)
        }
    }

    fn evaluate(input_data: &[u8], output_script: &[u8]) -> Result<(), ErrorKind> {
        Eval::default().run(input_data, output_script)
    }

    #[test]
    fn test_p2pkh_valid() {
        assert_eq!(evaluate(&from_hex(P2PKH_IN), &from_hex(P2PKH_OUT)), Ok(()));
    }

    #[test]
    fn test_p2pkh_wrong_sighash() {
        let eval = Eval::default();
        let config = config();
        let ctx = EvalContext {
            version: eval.version,
            sighash_all_data: b"a different sighash",
            timestamp: eval.timestamp,
            spent_output_value: eval.spent_output_value,
            tx_outputs: &eval.tx_outputs,
            config: &config,
        };
        let result = raw_script_eval(&from_hex(P2PKH_IN), &from_hex(P2PKH_OUT), &ctx);
        assert_eq!(
            result.map_err(|e| e.kind),
            Err(ErrorKind::FinalStackInvalid)
        );
    }

    #[test]
    fn test_p2pkh_timelock() {
        let input = from_hex(P2PKH_IN);
        let output = from_hex(P2PKH_OUT_TIMELOCK);
        assert_eq!(evaluate(&input, &output), Ok(()));
        let locked = Eval {
            timestamp: 900,
            ..Eval::default()
        };
        assert_eq!(locked.run(&input, &output), Err(ErrorKind::TimeLocked));
        // Boundary: timestamp == timelock is still locked (strict greater-than).
        let boundary = Eval {
            timestamp: 1000,
            ..Eval::default()
        };
        assert_eq!(boundary.run(&input, &output), Err(ErrorKind::TimeLocked));
    }

    #[test]
    fn test_multisig_valid() {
        assert_eq!(evaluate(&from_hex(MS_IN), &from_hex(MS_OUT)), Ok(()));
    }

    #[test]
    fn test_multisig_swapped_signatures() {
        // Signatures out of pubkey order fail the greedy in-order matching: the sub-checksig
        // pushes 0, so the redeem-script eval leaves a false value.
        let result = evaluate(&from_hex(MS_IN_SWAPPED), &from_hex(MS_OUT));
        assert_eq!(result, Err(ErrorKind::FinalStackInvalid));
    }

    #[test]
    fn test_multisig_input_without_pushes() {
        // OP_GREATERTHAN_TIMESTAMP alone: the first eval hits an empty stack.
        let result = evaluate(&[0x6F], &from_hex(MS_OUT));
        assert_eq!(result, Err(ErrorKind::MissingStackItems));
        assert_eq!(
            evaluate(&[], &from_hex(MS_OUT)),
            Err(ErrorKind::MissingStackItems)
        );
    }

    #[test]
    fn test_multisig_zero_of_zero() {
        // OP_0 OP_0 OP_CHECKMULTISIG pushes 1: 0-of-0 multisig is "valid".
        assert_eq!(
            evaluate(&[], &[0x50, 0x50, 0xAE, 0x51, 0x87]),
            Err(ErrorKind::AssertionFailed)
        );
        assert_eq!(evaluate(&[0x50, 0x50], &[0xAE]), Ok(()));
    }

    #[test]
    fn test_multisig_signature_count_limit() {
        // N=0 pubkeys, M=16 signatures: 16 > MAX_MULTISIG_SIGNATURES (15).
        let result = evaluate(&[0x60, 0x50], &[0xAE]);
        assert_eq!(result, Err(ErrorKind::InvalidStackData));
    }

    #[test]
    fn test_multisig_pubkey_count_not_integer() {
        // A bytes item where the pubkey count is expected.
        let result = evaluate(&[0x01, 0xAB], &[0xAE]);
        assert_eq!(result, Err(ErrorKind::InvalidStackData));
    }

    #[test]
    fn test_find_p2pkh() {
        let outputs = vec![(100u64, from_hex(P2PKH_OUT))];
        let input = from_hex(FIND_P2PKH_IN);
        let output = [0xD0];
        let v1 = Eval {
            version: OpcodesVersion::V1,
            tx_outputs: outputs.clone(),
            ..Eval::default()
        };
        assert_eq!(v1.run(&input, &output), Ok(()));
        // Value mismatch: no output matches the spent value.
        let wrong_value = Eval {
            version: OpcodesVersion::V1,
            spent_output_value: 99,
            tx_outputs: outputs.clone(),
            ..Eval::default()
        };
        assert_eq!(
            wrong_value.run(&input, &output),
            Err(ErrorKind::VerifyFailed)
        );
        // V1-only opcode under V2 is a plain ScriptError (it misses the dispatch table).
        let v2 = Eval {
            tx_outputs: outputs,
            ..Eval::default()
        };
        assert_eq!(v2.run(&input, &output), Err(ErrorKind::Script));
    }

    #[test]
    fn test_v1_only_opcodes_gated_under_v2() {
        for opcode in [0xBAu8, 0xC0, 0xC1, 0xD0, 0xD1] {
            assert_eq!(evaluate(&[0x51], &[opcode]), Err(ErrorKind::Script));
        }
    }

    #[test]
    fn test_assertion_on_int_operands() {
        // OP_1 OP_1 OP_EQUAL: Python asserts isinstance(elem, bytes) -> AssertionError.
        assert_eq!(
            evaluate(&[0x51, 0x51], &[0x87]),
            Err(ErrorKind::AssertionFailed)
        );
        // OP_HASH160 on an int.
        assert_eq!(evaluate(&[0x51], &[0xA9]), Err(ErrorKind::AssertionFailed));
    }

    #[test]
    fn test_invalid_opcode() {
        assert_eq!(evaluate(&[0x00], &[]), Err(ErrorKind::InvalidScript));
        assert_eq!(evaluate(&[0x4D], &[]), Err(ErrorKind::InvalidScript));
    }

    #[test]
    fn test_final_stack() {
        // Empty script -> empty stack.
        assert_eq!(evaluate(&[], &[]), Err(ErrorKind::FinalStackInvalid));
        // More than one item left.
        assert_eq!(
            evaluate(&[0x51, 0x51], &[]),
            Err(ErrorKind::FinalStackInvalid)
        );
        // A single int 1 is the only valid final stack.
        assert_eq!(evaluate(&[0x51], &[]), Ok(()));
        // int 0 is false.
        assert_eq!(evaluate(&[0x50], &[]), Err(ErrorKind::FinalStackInvalid));
        // bytes b"\x01" != int 1.
        assert_eq!(
            evaluate(&[0x01, 0x01], &[]),
            Err(ErrorKind::FinalStackInvalid)
        );
    }

    #[test]
    fn test_out_of_data() {
        assert_eq!(evaluate(&[0x4C], &[]), Err(ErrorKind::OutOfData));
        assert_eq!(evaluate(&[0x4C, 0x00], &[]), Err(ErrorKind::OutOfData));
        assert_eq!(evaluate(&[0x05, 0x01], &[]), Err(ErrorKind::OutOfData));
    }

    #[test]
    fn test_timelock_struct_error() {
        // A 3-byte timelock buffer: struct.unpack('!I') raises struct.error.
        let result = evaluate(&[0x03, 0x00, 0x00, 0x01, 0x6F, 0x51], &[]);
        assert_eq!(result, Err(ErrorKind::StructError));
    }

    #[test]
    fn test_op_dup() {
        assert_eq!(evaluate(&[], &[0x76]), Err(ErrorKind::MissingStackItems));
        // OP_1 OP_DUP leaves two items -> FinalStackInvalid (proves the dup happened).
        assert_eq!(
            evaluate(&[0x51], &[0x76]),
            Err(ErrorKind::FinalStackInvalid)
        );
    }

    #[test]
    fn test_op_equalverify() {
        // OP_1 goes first: OP_EQUALVERIFY consumes the two byte pushes above it, leaving int 1.
        let result = evaluate(&[0x51, 0x01, 0xAB, 0x01, 0xAB], &[0x88]);
        assert_eq!(result, Ok(()));
        let result = evaluate(&[0x51, 0x01, 0xAB, 0x01, 0xAC], &[0x88]);
        assert_eq!(result, Err(ErrorKind::EqualVerifyFailed));
        assert_eq!(
            evaluate(&[0x01, 0xAB], &[0x88]),
            Err(ErrorKind::MissingStackItems)
        );
    }

    #[test]
    fn test_checkdatasig_v1() {
        // Pushing data, a garbage signature and a valid-format pubkey: the signature does not
        // verify, so OP_CHECKDATASIG raises OracleChecksigFailed (unlike OP_CHECKSIG's push-0).
        let pubkey = from_hex("02bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020d");
        let mut input = vec![0x04, b'd', b'a', b't', b'a', 0x03, 0x30, 0x01, 0x02];
        input.push(0x21);
        input.extend_from_slice(&pubkey);
        let v1 = Eval {
            version: OpcodesVersion::V1,
            ..Eval::default()
        };
        assert_eq!(
            v1.run(&input, &[0xBA]),
            Err(ErrorKind::OracleChecksigFailed)
        );
    }

    #[test]
    fn test_data_strequal_v1() {
        let v1 = Eval {
            version: OpcodesVersion::V1,
            ..Eval::default()
        };
        // data = "03 abc": k=0 -> value "abc"; OP_DATA_STREQUAL pushes data back, then
        // OP_DATA_GREATERTHAN-style cleanup isn't needed: compare and leave data on stack.
        // Final stack holds data (bytes) -> FinalStackInvalid, proving the opcode succeeded.
        let mut input = vec![0x04, 0x03, b'a', b'b', b'c']; // push data
        input.push(0x50); // OP_0 -> k = 0
        input.extend_from_slice(&[0x03, b'a', b'b', b'c']); // push value
        assert_eq!(v1.run(&input, &[0xC0]), Err(ErrorKind::FinalStackInvalid));
        // Mismatching UTF-8 values -> VerifyFailed.
        let mut input = vec![0x04, 0x03, b'a', b'b', b'c'];
        input.push(0x50);
        input.extend_from_slice(&[0x03, b'x', b'y', b'z']);
        assert_eq!(v1.run(&input, &[0xC0]), Err(ErrorKind::VerifyFailed));
        // Mismatching with non-UTF-8 data: the Python error formatting decodes utf-8.
        let mut input = vec![0x04, 0x03, 0xFF, 0xFE, 0xFD];
        input.push(0x50);
        input.extend_from_slice(&[0x03, b'x', b'y', b'z']);
        assert_eq!(v1.run(&input, &[0xC0]), Err(ErrorKind::UnicodeDecode));
        // Non-int k -> VerifyFailed.
        let mut input = vec![0x04, 0x03, b'a', b'b', b'c'];
        input.extend_from_slice(&[0x01, 0x00]);
        input.extend_from_slice(&[0x03, b'a', b'b', b'c']);
        assert_eq!(v1.run(&input, &[0xC0]), Err(ErrorKind::VerifyFailed));
    }

    #[test]
    fn test_data_greaterthan_v1() {
        let v1 = Eval {
            version: OpcodesVersion::V1,
            ..Eval::default()
        };
        // data value 5 > 3 -> ok, data left on stack -> FinalStackInvalid.
        let mut input = vec![0x02, 0x01, 0x05]; // data: one 1-byte value 5
        input.push(0x50); // k = 0
        input.extend_from_slice(&[0x01, 0x03]); // value 3
        assert_eq!(v1.run(&input, &[0xC1]), Err(ErrorKind::FinalStackInvalid));
        // 5 <= 7 -> VerifyFailed.
        let mut input = vec![0x02, 0x01, 0x05];
        input.push(0x50);
        input.extend_from_slice(&[0x01, 0x07]);
        assert_eq!(v1.run(&input, &[0xC1]), Err(ErrorKind::VerifyFailed));
        // 3-byte integer buffer -> caught struct.error -> VerifyFailed.
        let mut input = vec![0x02, 0x01, 0x05];
        input.push(0x50);
        input.extend_from_slice(&[0x03, 0x00, 0x00, 0x07]);
        assert_eq!(v1.run(&input, &[0xC1]), Err(ErrorKind::VerifyFailed));
    }

    #[test]
    fn test_data_match_value_v1() {
        let v1 = Eval {
            version: OpcodesVersion::V1,
            ..Eval::default()
        };
        // Stack (bottom to top): data, k, last_pubkey, value0, pubkey0, n_items=1.
        // data's value at k=0 is 0x05, which matches value0 -> pubkey0 wins.
        let mut input = vec![0x02, 0x01, 0x05]; // data
        input.push(0x50); // k = 0
        input.extend_from_slice(&[0x02, b'L', b'P']); // last pubkey
        input.extend_from_slice(&[0x01, 0x05]); // value0 = 5
        input.extend_from_slice(&[0x02, b'P', b'0']); // pubkey0
        input.extend_from_slice(&[0x01, 0x01]); // n_items = 1 (as bytes)
        // winner pubkey (bytes) left on stack -> FinalStackInvalid proves success.
        assert_eq!(v1.run(&input, &[0xD1]), Err(ErrorKind::FinalStackInvalid));
        // data value at k with a 3-byte buffer: binary_to_int is OUTSIDE the try block in
        // Python -> uncaught struct.error.
        let mut input = vec![0x04, 0x03, 0x00, 0x00, 0x05];
        input.push(0x50);
        input.extend_from_slice(&[0x02, b'L', b'P']);
        input.extend_from_slice(&[0x01, 0x05]);
        input.extend_from_slice(&[0x02, b'P', b'0']);
        input.extend_from_slice(&[0x01, 0x01]);
        assert_eq!(v1.run(&input, &[0xD1]), Err(ErrorKind::StructError));
        // A 3-byte value0 buffer inside the loop is caught -> VerifyFailed.
        let mut input = vec![0x02, 0x01, 0x05];
        input.push(0x50);
        input.extend_from_slice(&[0x02, b'L', b'P']);
        input.extend_from_slice(&[0x03, 0x00, 0x00, 0x05]);
        input.extend_from_slice(&[0x02, b'P', b'0']);
        input.extend_from_slice(&[0x01, 0x01]);
        assert_eq!(v1.run(&input, &[0xD1]), Err(ErrorKind::VerifyFailed));
    }
}
