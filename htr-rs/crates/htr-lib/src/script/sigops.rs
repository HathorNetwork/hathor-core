//! Signature-operation counting: a faithful port of `SigopCounter` from
//! `hathor/transaction/scripts/construct.py`.

use crate::script::interpreter::get_multisig_data;
use crate::script::opcodes::{
    self, OP_0, OP_16, OP_CHECKDATASIG, OP_CHECKMULTISIG, OP_CHECKSIG, decode_opn,
};
use crate::script::{EvalError, matchers};

/// `SigopCounter.count_sigops`: walk the script counting the signature operations it would
/// execute. Mirrors the Python walk exactly, including its error behavior: `get_script_op`
/// validates every opcode, so a malformed script raises `OutOfData` / `InvalidScriptError`.
pub fn count_sigops(
    data: &[u8],
    max_multisig_pubkeys: u64,
    enable_checkdatasig_count: bool,
) -> Result<u64, EvalError> {
    let mut n_ops: u64 = 0;
    let data_len = data.len();
    let mut pos = 0;
    let mut last_opcode: Option<u8> = None;

    while pos < data_len {
        let (opcode, new_pos) = opcodes::get_script_op(pos, data, None)?;
        pos = new_pos;

        match opcode {
            OP_CHECKSIG => n_ops += 1,
            OP_CHECKMULTISIG => {
                if let Some(last) = last_opcode
                    && (OP_0..=OP_16).contains(&last)
                {
                    // Conventional multisig: the preceding OP_N is the pubkey count, the
                    // upper limit on checksig operations it can run.
                    let count = decode_opn(last)?;
                    n_ops += u64::try_from(count).expect("decode_opn returns 0..=16");
                } else {
                    // Unconventional multisig: count the pubkey limit (the upper bound).
                    n_ops += max_multisig_pubkeys;
                }
            }
            OP_CHECKDATASIG if enable_checkdatasig_count => n_ops += 1,
            _ => {}
        }
        last_opcode = Some(opcode);
    }
    Ok(n_ops)
}

/// `SigopCounter.get_sigops_count`: count sigops for a script; when an input's spent output
/// script is a MultiSig, the input data's redeem script is unwrapped (`get_multisig_data`,
/// which can itself fail on malformed input data) and counted instead.
pub fn get_sigops_count(
    data: &[u8],
    output_script: Option<&[u8]>,
    max_multisig_pubkeys: u64,
    enable_checkdatasig_count: bool,
) -> Result<u64, EvalError> {
    if let Some(output_script) = output_script
        && matchers::is_multisig_script(output_script)
    {
        let multisig_data = get_multisig_data(data)?;
        return count_sigops(
            &multisig_data,
            max_multisig_pubkeys,
            enable_checkdatasig_count,
        );
    }
    count_sigops(data, max_multisig_pubkeys, enable_checkdatasig_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::ErrorKind;

    const MAX_PUBKEYS: u64 = 20;

    fn count(data: &[u8]) -> Result<u64, ErrorKind> {
        count_sigops(data, MAX_PUBKEYS, true).map_err(|e| e.kind)
    }

    #[test]
    fn test_empty_script() {
        assert_eq!(count(&[]), Ok(0));
    }

    #[test]
    fn test_p2pkh_output_script() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG -> 1 sigop
        let mut script = vec![0x76, 0xA9, 0x14];
        script.extend_from_slice(&[0u8; 20]);
        script.extend_from_slice(&[0x88, 0xAC]);
        assert_eq!(count(&script), Ok(1));
    }

    #[test]
    fn test_checksig_repeated() {
        assert_eq!(count(&[0xAC, 0xAC, 0xAC]), Ok(3));
    }

    #[test]
    fn test_conventional_multisig() {
        // <OP_3> OP_CHECKMULTISIG: the preceding OP_N is the pubkey count.
        assert_eq!(count(&[0x53, 0xAE]), Ok(3));
        // OP_0 counts zero.
        assert_eq!(count(&[0x50, 0xAE]), Ok(0));
        // OP_16 counts sixteen.
        assert_eq!(count(&[0x60, 0xAE]), Ok(16));
    }

    #[test]
    fn test_unconventional_multisig() {
        // No preceding OP_N: counts the pubkey limit.
        assert_eq!(count(&[0xAE]), Ok(MAX_PUBKEYS));
        // A pushdata before it is not an OP_N: still the limit.
        assert_eq!(count(&[0x01, 0xAB, 0xAE]), Ok(MAX_PUBKEYS));
        // OP_N inside pushed data does not count: push of [0x53] then OP_CHECKMULTISIG.
        assert_eq!(count(&[0x01, 0x53, 0xAE]), Ok(MAX_PUBKEYS));
    }

    #[test]
    fn test_checkdatasig_gating() {
        assert_eq!(count_sigops(&[0xBA], MAX_PUBKEYS, true).unwrap(), 1);
        assert_eq!(count_sigops(&[0xBA], MAX_PUBKEYS, false).unwrap(), 0);
    }

    #[test]
    fn test_malformed_scripts() {
        // Invalid opcode -> InvalidScriptError (a TxValidationError in Python).
        assert_eq!(count(&[0x00]), Err(ErrorKind::InvalidScript));
        assert_eq!(count(&[0x4D]), Err(ErrorKind::InvalidScript));
        // Truncated push -> OutOfData (a ScriptError in Python).
        assert_eq!(count(&[0x05, 0x01]), Err(ErrorKind::OutOfData));
        assert_eq!(count(&[0x4C]), Err(ErrorKind::OutOfData));
    }

    #[test]
    fn test_get_sigops_count_multisig_output() {
        // 2-of-3 multisig: input data wraps the redeem script; the spent output script is
        // the multisig pattern, so the redeem script is unwrapped and counted.
        // redeem script: OP_2 <33B pk> <33B pk> <33B pk> OP_3 OP_CHECKMULTISIG
        let mut redeem = vec![0x52];
        for _ in 0..3 {
            redeem.push(0x21);
            redeem.extend_from_slice(&[0x02; 33]);
        }
        redeem.extend_from_slice(&[0x53, 0xAE]);
        // input data: <sig push> <redeem script push>
        let mut input_data = vec![0x05];
        input_data.extend_from_slice(&[0xAB; 5]);
        input_data.push(0x4C);
        input_data.push(u8::try_from(redeem.len()).unwrap());
        input_data.extend_from_slice(&redeem);
        // multisig output script: OP_HASH160 <20B> OP_EQUAL
        let mut output = vec![0xA9, 0x14];
        output.extend_from_slice(&[0u8; 20]);
        output.push(0x87);

        let result = get_sigops_count(&input_data, Some(&output), MAX_PUBKEYS, true);
        assert_eq!(result.unwrap(), 3);

        // Without the multisig output script, the raw input data has no sigops.
        let result = get_sigops_count(&input_data, None, MAX_PUBKEYS, true);
        assert_eq!(result.unwrap(), 0);

        // Multisig output but input data with no pushes: get_multisig_data IndexError.
        let result = get_sigops_count(&[0x6F], Some(&output), MAX_PUBKEYS, true);
        assert_eq!(result.unwrap_err().kind, ErrorKind::IndexError);
    }
}
