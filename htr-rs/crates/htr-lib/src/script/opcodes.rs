//! Byte-level script parsing: a faithful port of `hathor/transaction/scripts/execute.py`.

use crate::script::interpreter::StackItem;
use crate::script::{ErrorKind, EvalError};

pub const OP_PUSHDATA1: u8 = 0x4C;
pub const OP_0: u8 = 0x50;
pub const OP_16: u8 = 0x60;
pub const OP_GREATERTHAN_TIMESTAMP: u8 = 0x6F;
pub const OP_DUP: u8 = 0x76;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_HASH160: u8 = 0xA9;
pub const OP_CHECKSIG: u8 = 0xAC;
pub const OP_CHECKMULTISIG: u8 = 0xAE;
pub const OP_CHECKDATASIG: u8 = 0xBA;
pub const OP_DATA_STREQUAL: u8 = 0xC0;
pub const OP_DATA_GREATERTHAN: u8 = 0xC1;
pub const OP_FIND_P2PKH: u8 = 0xD0;
pub const OP_DATA_MATCH_VALUE: u8 = 0xD1;

/// `Opcode.is_pushdata`: opcodes that push data (bytes or an integer) onto the stack.
pub fn is_pushdata(opcode: u8) -> bool {
    (1..=75).contains(&opcode) || (OP_0..=OP_16).contains(&opcode) || opcode == OP_PUSHDATA1
}

/// `Opcode.is_valid_opcode`: pushdata opcodes plus every member of the `Opcode` enum.
pub fn is_valid_opcode(opcode: u8) -> bool {
    if is_pushdata(opcode) {
        return true;
    }
    matches!(
        opcode,
        OP_GREATERTHAN_TIMESTAMP
            | OP_DUP
            | OP_EQUAL
            | OP_EQUALVERIFY
            | OP_HASH160
            | OP_CHECKSIG
            | OP_CHECKMULTISIG
            | OP_CHECKDATASIG
            | OP_DATA_STREQUAL
            | OP_DATA_GREATERTHAN
            | OP_FIND_P2PKH
            | OP_DATA_MATCH_VALUE
    )
}

/// `decode_opn`: decode an `OP_N` opcode to its integer value (0..=16).
pub fn decode_opn(opcode: u8) -> Result<i64, EvalError> {
    if !(OP_0..=OP_16).contains(&opcode) {
        let message = format!("unknown opcode {opcode}");
        return Err(EvalError::new(ErrorKind::InvalidScript, message));
    }
    Ok(i64::from(opcode - OP_0))
}

/// `get_data_single_byte`: read one byte, `OutOfData` past the end.
fn get_data_single_byte(position: usize, data: &[u8]) -> Result<u8, EvalError> {
    if position >= data.len() {
        let message = format!(
            "trying to read a byte at {} outside of data, available {}",
            position,
            data.len()
        );
        return Err(EvalError::new(ErrorKind::OutOfData, message));
    }
    Ok(data[position])
}

/// `get_data_bytes`: extract `length` bytes starting at `position`, mirroring the Python
/// bound checks exactly (note: zero-length reads are rejected, so stack bytes are never empty).
fn get_data_bytes(position: usize, length: usize, data: &[u8]) -> Result<&[u8], EvalError> {
    if !(0 < length && length <= data.len()) {
        let message = format!("length ({length}) should be from 0 up to data length");
        return Err(EvalError::new(ErrorKind::OutOfData, message));
    }
    if !(0 < position && position < data.len()) {
        return Err(EvalError::new(
            ErrorKind::OutOfData,
            "position should be inside data",
        ));
    }
    if position + length > data.len() {
        let message = format!(
            "trying to read {} bytes starting at {}, available {}",
            length,
            position,
            data.len()
        );
        return Err(EvalError::new(ErrorKind::OutOfData, message));
    }
    Ok(&data[position..position + length])
}

/// `get_script_op`: interpret the opcode at `pos`, pushing extracted data onto `stack` when
/// given one, and return `(opcode, next_position)`.
pub fn get_script_op(
    pos: usize,
    data: &[u8],
    stack: Option<&mut Vec<StackItem>>,
) -> Result<(u8, usize), EvalError> {
    let opcode = get_data_single_byte(pos, data)?;

    if !is_valid_opcode(opcode) {
        let message = format!("Invalid Opcode ({opcode}) at position {pos}");
        return Err(EvalError::new(ErrorKind::InvalidScript, message));
    }

    if (1..=75).contains(&opcode) {
        // pushdata: push up to 75 bytes on stack
        let start = pos + 1;
        let bytes = get_data_bytes(start, opcode as usize, data)?;
        if let Some(stack) = stack {
            stack.push(StackItem::Bytes(bytes.to_vec()));
        }
        Ok((opcode, start + opcode as usize))
    } else if opcode == OP_PUSHDATA1 {
        // pushdata1: push up to 255 bytes on stack
        let length = get_data_single_byte(pos + 1, data)? as usize;
        let start = pos + 2;
        let bytes = get_data_bytes(start, length, data)?;
        if let Some(stack) = stack {
            stack.push(StackItem::Bytes(bytes.to_vec()));
        }
        Ok((opcode, start + length))
    } else if (OP_0..=OP_16).contains(&opcode) {
        // OP_N: push an integer (0 to 16) on stack
        let value = decode_opn(opcode)?;
        if let Some(stack) = stack {
            stack.push(StackItem::Int(value));
        }
        Ok((opcode, pos + 1))
    } else {
        // function opcode: just move to the next byte
        Ok((opcode, pos + 1))
    }
}

/// `get_data_value`: extract the kth length-prefixed value from `data`.
///
/// Quirk preserved from Python: a zero length byte yields an *empty* value (the reference
/// has a `TODO throw` that is a no-op `pass`).
pub fn get_data_value(k: i64, data: &[u8]) -> Result<&[u8], EvalError> {
    let data_len = data.len();
    let mut position = 0usize;
    let mut iteration: i64 = 0;
    while position < data_len {
        let length = data[position] as usize;
        position += 1;
        if position + length > data.len() {
            let message = format!(
                "trying to read {} bytes starting at {}, available {}",
                length,
                position,
                data.len()
            );
            return Err(EvalError::new(ErrorKind::OutOfData, message));
        }
        let value = &data[position..position + length];
        if iteration == k {
            return Ok(value);
        }
        iteration += 1;
        position += length;
    }
    Err(EvalError::new(ErrorKind::DataIndexError, ""))
}

/// `binary_to_int`: big-endian decode of 1/2/4/8 bytes; anything else is a `struct.error`.
pub fn binary_to_int(binary: &[u8]) -> Result<u64, EvalError> {
    match binary.len() {
        1 => Ok(u64::from(binary[0])),
        2 => Ok(u64::from(u16::from_be_bytes([binary[0], binary[1]]))),
        4 => {
            let array: [u8; 4] = binary.try_into().expect("length checked to be 4");
            Ok(u64::from(u32::from_be_bytes(array)))
        }
        8 => {
            let array: [u8; 8] = binary.try_into().expect("length checked to be 8");
            Ok(u64::from_be_bytes(array))
        }
        _ => Err(EvalError::new(ErrorKind::StructError, "")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(pos: usize, data: &[u8]) -> Result<(u8, usize, Vec<StackItem>), ErrorKind> {
        let mut stack = Vec::new();
        match get_script_op(pos, data, Some(&mut stack)) {
            Ok((opcode, next)) => Ok((opcode, next, stack)),
            Err(e) => Err(e.kind),
        }
    }

    #[test]
    fn test_get_script_op_pushdata() {
        let (opcode, next, stack) = parse(0, &[0x02, 0xAB, 0xCD]).unwrap();
        assert_eq!(opcode, 0x02);
        assert_eq!(next, 3);
        assert_eq!(stack, vec![StackItem::Bytes(vec![0xAB, 0xCD])]);
    }

    #[test]
    fn test_get_script_op_pushdata1() {
        let (opcode, next, stack) = parse(0, &[OP_PUSHDATA1, 0x02, 0xAB, 0xCD]).unwrap();
        assert_eq!(opcode, OP_PUSHDATA1);
        assert_eq!(next, 4);
        assert_eq!(stack, vec![StackItem::Bytes(vec![0xAB, 0xCD])]);
    }

    #[test]
    fn test_get_script_op_integers() {
        for value in 0..=16u8 {
            let (opcode, next, stack) = parse(0, &[OP_0 + value]).unwrap();
            assert_eq!(opcode, OP_0 + value);
            assert_eq!(next, 1);
            assert_eq!(stack, vec![StackItem::Int(i64::from(value))]);
        }
    }

    #[test]
    fn test_get_script_op_function_opcode() {
        let (opcode, next, stack) = parse(0, &[OP_DUP]).unwrap();
        assert_eq!(opcode, OP_DUP);
        assert_eq!(next, 1);
        assert_eq!(stack, vec![]);
    }

    #[test]
    fn test_get_script_op_invalid_opcodes() {
        for opcode in [0x00u8, 0x4D, 0x4E, 0x61, 0x75, 0xFF] {
            assert_eq!(parse(0, &[opcode]), Err(ErrorKind::InvalidScript));
        }
    }

    #[test]
    fn test_get_script_op_out_of_data() {
        // truncated direct push
        assert_eq!(parse(0, &[0x05, 0x01]), Err(ErrorKind::OutOfData));
        // push with no data at all
        assert_eq!(parse(0, &[0x01]), Err(ErrorKind::OutOfData));
        // pushdata1 missing the length byte
        assert_eq!(parse(0, &[OP_PUSHDATA1]), Err(ErrorKind::OutOfData));
        // pushdata1 with a zero length (rejected by get_data_bytes)
        assert_eq!(parse(0, &[OP_PUSHDATA1, 0x00]), Err(ErrorKind::OutOfData));
        // pushdata1 truncated
        assert_eq!(
            parse(0, &[OP_PUSHDATA1, 0x05, 0xAB]),
            Err(ErrorKind::OutOfData)
        );
        // reading past the end of data
        assert_eq!(parse(1, &[OP_DUP]), Err(ErrorKind::OutOfData));
    }

    #[test]
    fn test_decode_opn() {
        assert_eq!(decode_opn(OP_0).unwrap(), 0);
        assert_eq!(decode_opn(OP_16).unwrap(), 16);
        assert_eq!(decode_opn(0x61).unwrap_err().kind, ErrorKind::InvalidScript);
    }

    #[test]
    fn test_get_data_value() {
        let data = [0x03, b'a', b'b', b'c', 0x02, b'd', b'e'];
        assert_eq!(get_data_value(0, &data).unwrap(), b"abc");
        assert_eq!(get_data_value(1, &data).unwrap(), b"de");
        assert_eq!(
            get_data_value(2, &data).unwrap_err().kind,
            ErrorKind::DataIndexError
        );
        // zero length byte yields an empty value (Python's no-op `TODO throw`)
        let data = [0x00, 0x02, b'a', b'b'];
        assert_eq!(get_data_value(0, &data).unwrap(), b"");
        assert_eq!(get_data_value(1, &data).unwrap(), b"ab");
        // overrun
        let data = [0x05, b'a'];
        assert_eq!(
            get_data_value(0, &data).unwrap_err().kind,
            ErrorKind::OutOfData
        );
        // negative index never matches any iteration
        let data = [0x01, b'a'];
        assert_eq!(
            get_data_value(-1, &data).unwrap_err().kind,
            ErrorKind::DataIndexError
        );
    }

    #[test]
    fn test_binary_to_int() {
        assert_eq!(binary_to_int(&[0x80]).unwrap(), 0x80);
        assert_eq!(binary_to_int(&[0x01, 0x02]).unwrap(), 0x0102);
        assert_eq!(
            binary_to_int(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
            0x01020304
        );
        assert_eq!(
            binary_to_int(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]).unwrap(),
            0x0102030405060708
        );
        assert_eq!(binary_to_int(&[]).unwrap_err().kind, ErrorKind::StructError);
        assert_eq!(
            binary_to_int(&[0x01, 0x02, 0x03]).unwrap_err().kind,
            ErrorKind::StructError
        );
    }

    #[test]
    fn test_is_pushdata_and_validity() {
        assert!(is_pushdata(1));
        assert!(is_pushdata(75));
        assert!(is_pushdata(OP_PUSHDATA1));
        assert!(is_pushdata(OP_0));
        assert!(is_pushdata(OP_16));
        assert!(!is_pushdata(OP_DUP));
        assert!(!is_pushdata(0));
        assert!(is_valid_opcode(OP_CHECKSIG));
        assert!(is_valid_opcode(OP_DATA_MATCH_VALUE));
        assert!(!is_valid_opcode(0x00));
        assert!(!is_valid_opcode(0x4D));
        assert!(!is_valid_opcode(0x61));
    }
}
