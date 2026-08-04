//! Hand-rolled structural matchers replicating the compiled regexes from
//! `hathor/transaction/scripts/construct.py::re_compile`.
//!
//! The Python patterns are byte regexes built from `DATA_N` blocks, where
//! `DATA_N` compiles to `\x4C? <N as a literal length byte> .{N}` (the `OP_PUSHDATA1`
//! prefix is optional for N <= 75), with `re.DOTALL` so `.` matches any byte.
//! They are anchored `^...$` and applied with `.search` *without* `re.MULTILINE`,
//! so `$` also matches just before a single trailing `\n` (0x0A) — a script equal to a
//! valid pattern plus one trailing 0x0A byte matches. That quirk is consensus-visible
//! and replicated here by `anchored_at_end`.

use crate::script::opcodes::{
    OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_GREATERTHAN_TIMESTAMP, OP_HASH160,
    OP_PUSHDATA1,
};

/// `$`-equivalence: the pattern consumed `consumed` bytes from the start; it matches iff
/// the script ends there or has exactly one trailing newline byte after it.
fn anchored_at_end(script: &[u8], consumed: usize) -> bool {
    script.len() == consumed || (script.len() == consumed + 1 && script[consumed] == 0x0A)
}

/// Match the optional `(DATA_4) OP_GREATERTHAN_TIMESTAMP` timelock prefix at the start of
/// `script`, returning how many bytes each candidate decomposition consumes. The regex
/// tries the alternatives in greedy order: `\x4C`-present first, then without, then no
/// prefix at all. The candidates are mutually exclusive on their fixed bytes, but the
/// order is kept regex-faithful anyway.
fn timelock_prefix_lengths(script: &[u8]) -> [Option<usize>; 3] {
    let with_pushdata1 = (script.len() >= 7
        && script[0] == OP_PUSHDATA1
        && script[1] == 4
        && script[6] == OP_GREATERTHAN_TIMESTAMP)
        .then_some(7);
    let without_pushdata1 =
        (script.len() >= 6 && script[0] == 4 && script[5] == OP_GREATERTHAN_TIMESTAMP).then_some(6);
    [with_pushdata1, without_pushdata1, Some(0)]
}

/// Match a `DATA_20` block at `offset`, returning `(hash_start, consumed)`.
fn data20_at(script: &[u8], offset: usize) -> Option<(usize, usize)> {
    if script.len() >= offset + 22 && script[offset] == OP_PUSHDATA1 && script[offset + 1] == 20 {
        return Some((offset + 2, 22));
    }
    if script.len() >= offset + 21 && script[offset] == 20 {
        return Some((offset + 1, 21));
    }
    None
}

/// `MultiSig.re_match`: `^(?:(DATA_4) OP_GREATERTHAN_TIMESTAMP)? OP_HASH160 (DATA_20) OP_EQUAL$`.
pub fn is_multisig_script(script: &[u8]) -> bool {
    for prefix_len in timelock_prefix_lengths(script).into_iter().flatten() {
        if script.len() <= prefix_len || script[prefix_len] != OP_HASH160 {
            continue;
        }
        let Some((_, data20_consumed)) = data20_at(script, prefix_len + 1) else {
            continue;
        };
        let end = prefix_len + 1 + data20_consumed;
        if script.len() > end && script[end] == OP_EQUAL && anchored_at_end(script, end + 1) {
            return true;
        }
    }
    false
}

/// `P2PKH.re_match` + hash extraction, as used by `op_find_p2pkh` via `P2PKH.parse_script`:
/// `^(?:(DATA_4) OP_GREATERTHAN_TIMESTAMP)? OP_DUP OP_HASH160 (DATA_20) OP_EQUALVERIFY OP_CHECKSIG$`.
/// Returns the 20-byte public key hash on match.
pub fn parse_p2pkh_hash160(script: &[u8]) -> Option<[u8; 20]> {
    for prefix_len in timelock_prefix_lengths(script).into_iter().flatten() {
        if script.len() < prefix_len + 2
            || script[prefix_len] != OP_DUP
            || script[prefix_len + 1] != OP_HASH160
        {
            continue;
        }
        let Some((hash_start, data20_consumed)) = data20_at(script, prefix_len + 2) else {
            continue;
        };
        let end = prefix_len + 2 + data20_consumed;
        if script.len() > end + 1
            && script[end] == OP_EQUALVERIFY
            && script[end + 1] == OP_CHECKSIG
            && anchored_at_end(script, end + 2)
        {
            let hash: [u8; 20] = script[hash_start..hash_start + 20]
                .try_into()
                .expect("DATA_20 block always spans 20 bytes");
            return Some(hash);
        }
    }
    None
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

    // Vectors generated from the Python reference (MultiSig.re_match / P2PKH.re_match).
    const MS_OUT: &str = "a914435d1cb21e38a88634dfe325e1ec0fd5c98adc4387";
    const P2PKH_OUT: &str = "76a914a390bb4d6d4ab570767ef21f66c3edc1a4d6902688ac";
    const P2PKH_OUT_TIMELOCK: &str =
        "04000003e86f76a914a390bb4d6d4ab570767ef21f66c3edc1a4d6902688ac";
    const HASH160: &str = "a390bb4d6d4ab570767ef21f66c3edc1a4d69026";

    #[test]
    fn test_multisig_plain() {
        let script = from_hex(MS_OUT);
        assert!(is_multisig_script(&script));
    }

    #[test]
    fn test_multisig_trailing_newline_quirk() {
        // `$` without re.MULTILINE also matches just before one trailing 0x0A.
        let script = from_hex(MS_OUT);
        let mut with_newline = script.clone();
        with_newline.push(0x0A);
        assert!(is_multisig_script(&with_newline));
        let mut with_two = with_newline.clone();
        with_two.push(0x0A);
        assert!(!is_multisig_script(&with_two));
        let mut with_other = script;
        with_other.push(0x00);
        assert!(!is_multisig_script(&with_other));
    }

    #[test]
    fn test_multisig_pushdata1_variant() {
        // DATA_20 compiles to `\x4C? \x14 .{20}` — the OP_PUSHDATA1 prefix is optional.
        let mut script = vec![0xA9, 0x4C, 0x14];
        script.extend_from_slice(&[0u8; 20]);
        script.push(0x87);
        assert!(is_multisig_script(&script));
    }

    #[test]
    fn test_multisig_timelock_variants() {
        let core = &from_hex(MS_OUT);
        let mut with_timelock = vec![0x04, 0, 0, 0x03, 0xE8, 0x6F];
        with_timelock.extend_from_slice(core);
        assert!(is_multisig_script(&with_timelock));
        let mut with_pushdata1_timelock = vec![0x4C, 0x04, 0, 0, 0x03, 0xE8, 0x6F];
        with_pushdata1_timelock.extend_from_slice(core);
        assert!(is_multisig_script(&with_pushdata1_timelock));
    }

    #[test]
    fn test_multisig_rejections() {
        assert!(!is_multisig_script(&[]));
        assert!(!is_multisig_script(&[0xA9]));
        // wrong tail opcode
        let mut script = from_hex(MS_OUT);
        *script.last_mut().unwrap() = 0x88;
        assert!(!is_multisig_script(&script));
        // truncated hash
        let script = from_hex(MS_OUT);
        assert!(!is_multisig_script(&script[..script.len() - 2]));
        // P2PKH is not multisig
        assert!(!is_multisig_script(&from_hex(P2PKH_OUT)));
    }

    #[test]
    fn test_p2pkh_plain() {
        let script = from_hex(P2PKH_OUT);
        assert_eq!(
            parse_p2pkh_hash160(&script),
            Some(from_hex(HASH160).try_into().unwrap())
        );
    }

    #[test]
    fn test_p2pkh_timelock() {
        let script = from_hex(P2PKH_OUT_TIMELOCK);
        assert_eq!(
            parse_p2pkh_hash160(&script),
            Some(from_hex(HASH160).try_into().unwrap())
        );
        let mut with_pushdata1_timelock = vec![0x4C, 0x04, 0, 0, 0x03, 0xE8, 0x6F];
        with_pushdata1_timelock.extend_from_slice(&from_hex(P2PKH_OUT));
        assert_eq!(
            parse_p2pkh_hash160(&with_pushdata1_timelock),
            Some(from_hex(HASH160).try_into().unwrap())
        );
    }

    #[test]
    fn test_p2pkh_pushdata1_variant() {
        let mut script = vec![0x76, 0xA9, 0x4C, 0x14];
        script.extend_from_slice(&from_hex(HASH160));
        script.extend_from_slice(&[0x88, 0xAC]);
        assert_eq!(
            parse_p2pkh_hash160(&script),
            Some(from_hex(HASH160).try_into().unwrap())
        );
    }

    #[test]
    fn test_p2pkh_trailing_newline_quirk() {
        let mut script = from_hex(P2PKH_OUT);
        script.push(0x0A);
        assert_eq!(
            parse_p2pkh_hash160(&script),
            Some(from_hex(HASH160).try_into().unwrap())
        );
        script.push(0x0A);
        assert_eq!(parse_p2pkh_hash160(&script), None);
    }

    #[test]
    fn test_p2pkh_rejections() {
        assert_eq!(parse_p2pkh_hash160(&[]), None);
        assert_eq!(parse_p2pkh_hash160(&from_hex(MS_OUT)), None);
        let script = from_hex(P2PKH_OUT);
        assert_eq!(parse_p2pkh_hash160(&script[..script.len() - 1]), None);
        let mut wrong_tail = from_hex(P2PKH_OUT);
        *wrong_tail.last_mut().unwrap() = 0xAE;
        assert_eq!(parse_p2pkh_hash160(&wrong_tail), None);
    }
}
