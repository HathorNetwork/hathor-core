//! Vertex wire-format parsing: a faithful port of the deserialization in
//! `hathor/transaction/vertex_parser/` for the hot-path vertex types.
//!
//! Conservative-acceptance contract: `parse_vertex` returns `Some(fields)` only when the bytes
//! are a fully valid serialization of a supported vertex (regular block, regular transaction or
//! token-creation transaction, with **no headers**). Anything else — unsupported version,
//! headers present, malformed bytes, size violations — returns `None` and the Python parser
//! handles it, preserving Python's exact rejection semantics. Differential round-trip tests
//! guarantee that whenever Rust accepts, Python accepts with an identical vertex.

use pyo3::prelude::*;
use sha2::{Digest, Sha256};

const TX_HASH_SIZE: usize = 32;
const VERSION_REGULAR_BLOCK: u8 = 0;
const VERSION_REGULAR_TRANSACTION: u8 = 1;
const VERSION_TOKEN_CREATION_TRANSACTION: u8 = 2;
const MAX_OUTPUT_VALUE_32: u64 = (1 << 31) - 1;
const MAX_OUTPUT_VALUE_64: u64 = 1 << 63;
/// The mining nonce is always hashed as 16 big-endian bytes, regardless of the (smaller)
/// serialization nonce size used by transactions.
const HASH_NONCE_SIZE: usize = 16;
/// Token versions accepted by Python's `TokenVersion(raw)`: STANDARD/DEPOSIT/ETHEREUM.
const MAX_TOKEN_VERSION: u8 = 2;

type ParsedInput = (Vec<u8>, u8, Vec<u8>);
type ParsedOutput = (u64, Vec<u8>, u8);

/// The parsed field tree handed back to Python for object construction:
/// `(version, signal_bits, weight, timestamp, nonce, hash, parents, tokens, inputs, outputs,
///   block_data, token_info)`.
type ParsedVertex = (
    u8,
    u8,
    f64,
    u32,
    u128,
    Vec<u8>,
    Vec<Vec<u8>>,
    Vec<Vec<u8>>,
    Vec<ParsedInput>,
    Vec<ParsedOutput>,
    Vec<u8>,
    Option<(u8, String, String)>,
);

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn f64(&mut self) -> Option<f64> {
        let b = self.take(8)?;
        Some(f64::from_be_bytes(
            b.try_into().expect("take(8) returns 8 bytes"),
        ))
    }

    fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }
}

/// `decode_output_value_v1` with `strict=True`: 4-byte signed when the first byte is
/// non-negative, else 8-byte signed storing the negated value. Rejects zero, the
/// fits-in-4-bytes-but-used-8 case, and out-of-range values — exactly like Python.
fn decode_output_value(r: &mut Reader<'_>) -> Option<u64> {
    let first = *r.data.get(r.pos)?;
    let value: i128 = if first & 0x80 != 0 {
        let b = r.take(8)?;
        let raw = i64::from_be_bytes(b.try_into().expect("take(8) returns 8 bytes"));
        // raw is negative; the value is its negation (use i128: -i64::MIN overflows i64)
        let value = -(raw as i128);
        if value <= MAX_OUTPUT_VALUE_32 as i128 {
            return None; // "Value fits in 4 bytes but is using 8 bytes"
        }
        value
    } else {
        let b = r.take(4)?;
        i32::from_be_bytes(b.try_into().expect("take(4) returns 4 bytes")) as i128
    };
    if value <= 0 || value > MAX_OUTPUT_VALUE_64 as i128 {
        return None;
    }
    Some(value as u64)
}

fn parse_inputs(r: &mut Reader<'_>, count: u8) -> Option<Vec<ParsedInput>> {
    let mut inputs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let tx_id = r.take(TX_HASH_SIZE)?.to_vec();
        let index = r.u8()?;
        let data_len = r.u16()? as usize;
        let data = r.take(data_len)?.to_vec();
        inputs.push((tx_id, index, data));
    }
    Some(inputs)
}

fn parse_outputs(r: &mut Reader<'_>, count: u8) -> Option<Vec<ParsedOutput>> {
    let mut outputs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let value = decode_output_value(r)?;
        let token_data = r.u8()?;
        let script_len = r.u16()? as usize;
        let script = r.take(script_len)?.to_vec();
        outputs.push((value, script, token_data));
    }
    Some(outputs)
}

struct GraphFields {
    weight: f64,
    timestamp: u32,
    parents: Vec<Vec<u8>>,
}

fn parse_graph(r: &mut Reader<'_>) -> Option<GraphFields> {
    let weight = r.f64()?;
    let timestamp = r.u32()?;
    let parents_len = r.u8()?;
    let mut parents = Vec::with_capacity(parents_len as usize);
    for _ in 0..parents_len {
        parents.push(r.take(TX_HASH_SIZE)?.to_vec());
    }
    Some(GraphFields {
        weight,
        timestamp,
        parents,
    })
}

/// `calculate_hash`: reverse(sha256(sha256(sha256(funds) || sha256(graph || headers) || nonce16))).
/// The supported vertices have no headers, so the graph slice alone feeds the second hash.
fn compute_hash(funds: &[u8], graph: &[u8], nonce: u128) -> Vec<u8> {
    let funds_hash = Sha256::digest(funds);
    let graph_hash = Sha256::digest(graph);
    let mut inner = Sha256::new();
    inner.update(funds_hash);
    inner.update(graph_hash);
    inner.update(&nonce.to_be_bytes()[16 - HASH_NONCE_SIZE..]);
    let mut hash: Vec<u8> = Sha256::digest(inner.finalize()).to_vec();
    hash.reverse();
    hash
}

fn parse(data: &[u8]) -> Option<ParsedVertex> {
    let mut r = Reader::new(data);
    let signal_bits = r.u8()?;
    let version = r.u8()?;

    let (tokens, inputs, outputs, token_info, nonce_size) = match version {
        VERSION_REGULAR_BLOCK => {
            let outputs_len = r.u8()?;
            let outputs = parse_outputs(&mut r, outputs_len)?;
            (vec![], vec![], outputs, None, 16usize)
        }
        VERSION_REGULAR_TRANSACTION => {
            let tokens_len = r.u8()?;
            let inputs_len = r.u8()?;
            let outputs_len = r.u8()?;
            let mut tokens = Vec::with_capacity(tokens_len as usize);
            for _ in 0..tokens_len {
                tokens.push(r.take(TX_HASH_SIZE)?.to_vec());
            }
            let inputs = parse_inputs(&mut r, inputs_len)?;
            let outputs = parse_outputs(&mut r, outputs_len)?;
            (tokens, inputs, outputs, None, 4usize)
        }
        VERSION_TOKEN_CREATION_TRANSACTION => {
            let inputs_len = r.u8()?;
            let outputs_len = r.u8()?;
            let inputs = parse_inputs(&mut r, inputs_len)?;
            let outputs = parse_outputs(&mut r, outputs_len)?;
            let token_version = r.u8()?;
            if token_version > MAX_TOKEN_VERSION {
                return None;
            }
            let name_len = r.u8()? as usize;
            let name = String::from_utf8(r.take(name_len)?.to_vec()).ok()?;
            let symbol_len = r.u8()? as usize;
            let symbol = String::from_utf8(r.take(symbol_len)?.to_vec()).ok()?;
            (
                vec![],
                inputs,
                outputs,
                Some((token_version, name, symbol)),
                4usize,
            )
        }
        // merge-mined / PoA / on-chain-blueprint: Python fallback
        _ => return None,
    };

    let funds_end = r.pos;
    let graph = parse_graph(&mut r)?;
    let block_data = if version == VERSION_REGULAR_BLOCK {
        let data_len = r.u8()? as usize;
        r.take(data_len)?.to_vec()
    } else {
        vec![]
    };
    let graph_end = r.pos;

    let nonce_bytes = r.take(nonce_size)?;
    let mut nonce: u128 = 0;
    for &b in nonce_bytes {
        nonce = (nonce << 8) | b as u128;
    }

    // any remaining bytes are headers (or trailing garbage): Python fallback
    if !r.is_empty() {
        return None;
    }

    let hash = compute_hash(&data[..funds_end], &data[funds_end..graph_end], nonce);

    Some((
        version,
        signal_bits,
        graph.weight,
        graph.timestamp,
        nonce,
        hash,
        graph.parents,
        tokens,
        inputs,
        outputs,
        block_data,
        token_info,
    ))
}

/// Parse a serialized vertex, returning the field tree (plus the computed vertex hash) for
/// Python-side object construction, or `None` when the bytes are not a fully valid
/// serialization of a supported vertex (the caller falls back to the Python parser).
#[pyfunction]
pub fn parse_vertex(data: Vec<u8>, max_size: usize) -> Option<ParsedVertex> {
    if data.len() > max_size {
        return None; // Python raises SerializedSizeError with the proper message
    }
    parse(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 1-input/1-output regular transaction generated by the Python serializer; the expected
    // hash was computed by Python's update_hash.
    fn build_tx_bytes() -> Vec<u8> {
        let mut d = vec![0x00, 0x01, 0x00, 0x01, 0x01]; // sb, version, tokens, inputs, outputs
        d.extend_from_slice(&[0x11; 32]); // input tx_id
        d.push(0x00); // input index
        d.extend_from_slice(&[0x00, 0x03]); // data len
        d.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // data
        d.extend_from_slice(&100i32.to_be_bytes()); // output value (4B)
        d.push(0x00); // token_data
        d.extend_from_slice(&[0x00, 0x01, 0x51]); // script len + script
        d.extend_from_slice(&10.5f64.to_be_bytes()); // weight
        d.extend_from_slice(&1000u32.to_be_bytes()); // timestamp
        d.push(0x01); // parents len
        d.extend_from_slice(&[0x22; 32]); // parent
        d.extend_from_slice(&7u32.to_be_bytes()); // nonce (4B for txs)
        d
    }

    #[test]
    fn test_parse_regular_transaction() {
        let data = build_tx_bytes();
        let parsed = parse(&data).unwrap();
        let (
            version,
            signal_bits,
            weight,
            timestamp,
            nonce,
            hash,
            parents,
            tokens,
            inputs,
            outputs,
            block_data,
            token_info,
        ) = parsed;
        assert_eq!(version, 1);
        assert_eq!(signal_bits, 0);
        assert_eq!(weight, 10.5);
        assert_eq!(timestamp, 1000);
        assert_eq!(nonce, 7);
        assert_eq!(hash.len(), 32);
        assert_eq!(parents, vec![vec![0x22; 32]]);
        assert!(tokens.is_empty());
        assert_eq!(inputs, vec![(vec![0x11; 32], 0, vec![0xAA, 0xBB, 0xCC])]);
        assert_eq!(outputs, vec![(100, vec![0x51], 0)]);
        assert!(block_data.is_empty());
        assert!(token_info.is_none());
    }

    #[test]
    fn test_truncations_rejected() {
        let data = build_tx_bytes();
        for cut in 0..data.len() {
            assert!(
                parse(&data[..cut]).is_none(),
                "truncation at {cut} accepted"
            );
        }
    }

    #[test]
    fn test_trailing_bytes_rejected() {
        let mut data = build_tx_bytes();
        data.push(0x00);
        assert!(parse(&data).is_none());
    }

    #[test]
    fn test_unsupported_versions_rejected() {
        for version in [3u8, 5, 6, 7, 0xFF] {
            let mut data = build_tx_bytes();
            data[1] = version;
            assert!(parse(&data).is_none());
        }
    }

    #[test]
    fn test_output_value_encoding() {
        // 8-byte encoding for a value above 2^31-1
        let mut d = vec![0x00, 0x01, 0x00, 0x00, 0x01]; // tx with 0 inputs, 1 output
        let value: u64 = 5_000_000_000;
        d.extend_from_slice(&(-(value as i64)).to_be_bytes());
        d.push(0x00);
        d.extend_from_slice(&[0x00, 0x01, 0x51]);
        d.extend_from_slice(&1.0f64.to_be_bytes());
        d.extend_from_slice(&1u32.to_be_bytes());
        d.push(0x00); // no parents
        d.extend_from_slice(&0u32.to_be_bytes()); // nonce
        let parsed = parse(&d).unwrap();
        assert_eq!(parsed.9, vec![(5_000_000_000, vec![0x51], 0)]);

        // a small value wrongly using 8 bytes is rejected
        let mut bad = vec![0x00, 0x01, 0x00, 0x00, 0x01];
        bad.extend_from_slice(&(-100i64).to_be_bytes());
        bad.push(0x00);
        bad.extend_from_slice(&[0x00, 0x01, 0x51]);
        assert!(parse(&bad).is_none());

        // zero value is rejected (strict)
        let mut zero = vec![0x00, 0x01, 0x00, 0x00, 0x01];
        zero.extend_from_slice(&0i32.to_be_bytes());
        zero.push(0x00);
        zero.extend_from_slice(&[0x00, 0x01, 0x51]);
        assert!(parse(&zero).is_none());
    }

    #[test]
    fn test_parse_block() {
        let mut d = vec![0x00, 0x00, 0x01]; // sb, version=block, outputs=1
        d.extend_from_slice(&6400i32.to_be_bytes());
        d.push(0x00);
        d.extend_from_slice(&[0x00, 0x01, 0x51]);
        d.extend_from_slice(&21.0f64.to_be_bytes());
        d.extend_from_slice(&2000u32.to_be_bytes());
        d.push(0x03); // 3 parents
        for i in 0..3u8 {
            d.extend_from_slice(&[i; 32]);
        }
        d.push(0x02); // data len
        d.extend_from_slice(&[0xDE, 0xAD]);
        d.extend_from_slice(&[0x00; 12]); // nonce high bytes
        d.extend_from_slice(&42u32.to_be_bytes()); // nonce low (16B total)
        let parsed = parse(&d).unwrap();
        assert_eq!(parsed.0, 0);
        assert_eq!(parsed.4, 42);
        assert_eq!(parsed.6.len(), 3);
        assert_eq!(parsed.10, vec![0xDE, 0xAD]);
    }
}
