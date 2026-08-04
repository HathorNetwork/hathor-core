//! Mutable transaction metadata: the canonical binary storage format (version 1).
//!
//! `hathor/transaction/transaction_metadata.py` is the reference; this replaces its JSON
//! storage encoding (which spent most of its time hex-encoding hashes and building dicts).
//! Hot fields are flat binary with raw 32-byte hashes; the rare nano fields keep their JSON
//! encoding embedded as a length-prefixed blob, so the format stays simple where it matters.
//!
//! Layout (integers big-endian; `hashes` = u16 count + count * 32 bytes):
//! ```text
//! [0] format version (1)
//! [1] flags: 1 has_hash | 2 has_first_block | 4 has_feature_states
//!            | 8 has_nc_block_root_id | 16 has_nc_execution | 32 has_nc_calls
//!            | 64 has_nc_events
//! validation: len u8 + utf8 (the lowercase ValidationState name)
//! accumulated_weight: len u8 + minimal big-endian bytes (unbounded int)
//! score: len u8 + minimal big-endian bytes
//! hash [32] (if flag) | first_block [32] (if flag)
//! voided_by: u16 count + count * (len u8 + bytes) — entries are usually 32-byte hashes
//!            but can be short sentinel markers (soft-voided, consensus-fail, partial);
//!            empty round-trips to None, mirroring the JSON semantics
//! conflict_with: hashes (same)
//! twins: hashes
//! received_by: u16 count + count * u64
//! spent_outputs: u16 count + count * (index u8, hashes)
//! feature_states (if flag): u16 count + count * (name: len u8 + utf8, state: len u8 + utf8)
//! nc_block_root_id [32] (if flag)
//! nc_execution (if flag): len u8 + utf8
//! nc_calls (if flag): u32 len + embedded JSON bytes
//! nc_events (if flag): u16 count + count * (nc_id [32], data: u32 len + bytes)
//! ```

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

const FORMAT_VERSION: u8 = 1;
const HASH_SIZE: usize = 32;

const F_HASH: u8 = 1;
const F_FIRST_BLOCK: u8 = 2;
const F_FEATURE_STATES: u8 = 4;
const F_NC_BLOCK_ROOT_ID: u8 = 8;
const F_NC_EXECUTION: u8 = 16;
const F_NC_CALLS: u8 = 32;
const F_NC_EVENTS: u8 = 64;

fn put_str(out: &mut Vec<u8>, value: &str) {
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
}

fn put_short_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

fn put_hashes(out: &mut Vec<u8>, hashes: &[Vec<u8>]) {
    out.extend_from_slice(&(hashes.len() as u16).to_be_bytes());
    for hash in hashes {
        debug_assert_eq!(hash.len(), HASH_SIZE);
        out.extend_from_slice(hash);
    }
}

/// Serialize a metadata record. Field order and semantics follow the module docs; the caller
/// (Python `TransactionMetadata.to_bytes`) flattens its object into these arguments.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn metadata_to_bytes(
    hash: Option<Vec<u8>>,
    validation: String,
    accumulated_weight_be: Vec<u8>,
    score_be: Vec<u8>,
    first_block: Option<Vec<u8>>,
    voided_by: Vec<Vec<u8>>,
    conflict_with: Vec<Vec<u8>>,
    twins: Vec<Vec<u8>>,
    received_by: Vec<u64>,
    spent_outputs: Vec<(u8, Vec<Vec<u8>>)>,
    feature_states: Option<Vec<(String, String)>>,
    nc_block_root_id: Option<Vec<u8>>,
    nc_execution: Option<String>,
    nc_calls_json: Option<Vec<u8>>,
    nc_events: Option<Vec<(Vec<u8>, Vec<u8>)>>,
) -> PyResult<Vec<u8>> {
    for hash_field in [&hash, &first_block, &nc_block_root_id] {
        if let Some(value) = hash_field
            && value.len() != HASH_SIZE
        {
            return Err(PyValueError::new_err("hash fields must be 32 bytes"));
        }
    }

    let mut flags = 0u8;
    if hash.is_some() {
        flags |= F_HASH;
    }
    if first_block.is_some() {
        flags |= F_FIRST_BLOCK;
    }
    if feature_states.is_some() {
        flags |= F_FEATURE_STATES;
    }
    if nc_block_root_id.is_some() {
        flags |= F_NC_BLOCK_ROOT_ID;
    }
    if nc_execution.is_some() {
        flags |= F_NC_EXECUTION;
    }
    if nc_calls_json.is_some() {
        flags |= F_NC_CALLS;
    }
    if nc_events.is_some() {
        flags |= F_NC_EVENTS;
    }

    for entry in &voided_by {
        if entry.len() > u8::MAX as usize {
            return Err(PyValueError::new_err(
                "voided_by entries must fit in 255 bytes",
            ));
        }
    }

    let mut out = Vec::with_capacity(256);
    out.push(FORMAT_VERSION);
    out.push(flags);
    put_str(&mut out, &validation);
    put_short_bytes(&mut out, &accumulated_weight_be);
    put_short_bytes(&mut out, &score_be);
    if let Some(value) = &hash {
        out.extend_from_slice(value);
    }
    if let Some(value) = &first_block {
        out.extend_from_slice(value);
    }
    // voided_by entries are variable-length: besides tx hashes they can carry the
    // soft-voided / consensus-fail / partially-validated sentinel markers
    out.extend_from_slice(&(voided_by.len() as u16).to_be_bytes());
    for entry in &voided_by {
        put_short_bytes(&mut out, entry);
    }
    put_hashes(&mut out, &conflict_with);
    put_hashes(&mut out, &twins);
    out.extend_from_slice(&(received_by.len() as u16).to_be_bytes());
    for value in &received_by {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&(spent_outputs.len() as u16).to_be_bytes());
    for (index, hashes) in &spent_outputs {
        out.push(*index);
        put_hashes(&mut out, hashes);
    }
    if let Some(states) = &feature_states {
        out.extend_from_slice(&(states.len() as u16).to_be_bytes());
        for (name, state) in states {
            put_str(&mut out, name);
            put_str(&mut out, state);
        }
    }
    if let Some(value) = &nc_block_root_id {
        out.extend_from_slice(value);
    }
    if let Some(value) = &nc_execution {
        put_str(&mut out, value);
    }
    if let Some(blob) = &nc_calls_json {
        out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        out.extend_from_slice(blob);
    }
    if let Some(events) = &nc_events {
        out.extend_from_slice(&(events.len() as u16).to_be_bytes());
        for (nc_id, data) in events {
            if nc_id.len() != HASH_SIZE {
                return Err(PyValueError::new_err("nc_event ids must be 32 bytes"));
            }
            out.extend_from_slice(nc_id);
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
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
        Some(u32::from_be_bytes(
            b.try_into().expect("take(4) returns 4 bytes"),
        ))
    }

    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        Some(u64::from_be_bytes(
            b.try_into().expect("take(8) returns 8 bytes"),
        ))
    }

    fn string(&mut self) -> Option<String> {
        let len = self.u8()? as usize;
        String::from_utf8(self.take(len)?.to_vec()).ok()
    }

    fn short_bytes(&mut self) -> Option<Vec<u8>> {
        let len = self.u8()? as usize;
        Some(self.take(len)?.to_vec())
    }

    fn hash(&mut self) -> Option<Vec<u8>> {
        Some(self.take(HASH_SIZE)?.to_vec())
    }

    fn hashes(&mut self) -> Option<Vec<Vec<u8>>> {
        let count = self.u16()? as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.hash()?);
        }
        Some(out)
    }
}

/// The decoded record as two nested tuples (pyo3 converts tuples up to 12 elements):
/// core fields and the rare nano/feature extras.
type MetadataCore = (
    Option<Vec<u8>>,         // hash
    String,                  // validation
    Vec<u8>,                 // accumulated_weight (minimal BE)
    Vec<u8>,                 // score (minimal BE)
    Option<Vec<u8>>,         // first_block
    Vec<Vec<u8>>,            // voided_by
    Vec<Vec<u8>>,            // conflict_with
    Vec<Vec<u8>>,            // twins
    Vec<u64>,                // received_by
    Vec<(u8, Vec<Vec<u8>>)>, // spent_outputs
);
type MetadataExtra = (
    Option<Vec<(String, String)>>,   // feature_states
    Option<Vec<u8>>,                 // nc_block_root_id
    Option<String>,                  // nc_execution
    Option<Vec<u8>>,                 // nc_calls (embedded JSON)
    Option<Vec<(Vec<u8>, Vec<u8>)>>, // nc_events
);
type MetadataTuple = (MetadataCore, MetadataExtra);

fn decode(data: &[u8]) -> Option<MetadataTuple> {
    let mut r = Reader { data, pos: 0 };
    if r.u8()? != FORMAT_VERSION {
        return None;
    }
    let flags = r.u8()?;
    let validation = r.string()?;
    let accumulated_weight = r.short_bytes()?;
    let score = r.short_bytes()?;
    let hash = if flags & F_HASH != 0 {
        Some(r.hash()?)
    } else {
        None
    };
    let first_block = if flags & F_FIRST_BLOCK != 0 {
        Some(r.hash()?)
    } else {
        None
    };
    let voided_count = r.u16()? as usize;
    let mut voided_by = Vec::with_capacity(voided_count);
    for _ in 0..voided_count {
        voided_by.push(r.short_bytes()?);
    }
    let conflict_with = r.hashes()?;
    let twins = r.hashes()?;
    let received_count = r.u16()? as usize;
    let mut received_by = Vec::with_capacity(received_count);
    for _ in 0..received_count {
        received_by.push(r.u64()?);
    }
    let spent_count = r.u16()? as usize;
    let mut spent_outputs = Vec::with_capacity(spent_count);
    for _ in 0..spent_count {
        let index = r.u8()?;
        spent_outputs.push((index, r.hashes()?));
    }
    let feature_states = if flags & F_FEATURE_STATES != 0 {
        let count = r.u16()? as usize;
        let mut states = Vec::with_capacity(count);
        for _ in 0..count {
            let name = r.string()?;
            let state = r.string()?;
            states.push((name, state));
        }
        Some(states)
    } else {
        None
    };
    let nc_block_root_id = if flags & F_NC_BLOCK_ROOT_ID != 0 {
        Some(r.hash()?)
    } else {
        None
    };
    let nc_execution = if flags & F_NC_EXECUTION != 0 {
        Some(r.string()?)
    } else {
        None
    };
    let nc_calls = if flags & F_NC_CALLS != 0 {
        let len = r.u32()? as usize;
        Some(r.take(len)?.to_vec())
    } else {
        None
    };
    let nc_events = if flags & F_NC_EVENTS != 0 {
        let count = r.u16()? as usize;
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            let nc_id = r.hash()?;
            let len = r.u32()? as usize;
            events.push((nc_id, r.take(len)?.to_vec()));
        }
        Some(events)
    } else {
        None
    };
    if r.pos != data.len() {
        return None;
    }
    Some((
        (
            hash,
            validation,
            accumulated_weight,
            score,
            first_block,
            voided_by,
            conflict_with,
            twins,
            received_by,
            spent_outputs,
        ),
        (
            feature_states,
            nc_block_root_id,
            nc_execution,
            nc_calls,
            nc_events,
        ),
    ))
}

/// Parse a metadata record (see `metadata_to_bytes` for the tuple order). A stored record
/// that fails to parse is database corruption (or a format bug): it raises.
#[pyfunction]
pub fn metadata_from_bytes(data: Vec<u8>) -> PyResult<MetadataTuple> {
    decode(&data).ok_or_else(|| PyValueError::new_err("invalid metadata record"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        metadata_to_bytes(
            Some(vec![0x11; 32]),
            "full".to_string(),
            vec![0x05, 0x00],
            vec![0x01],
            Some(vec![0x22; 32]),
            vec![vec![0x33; 32], b"tx-non-grata".to_vec()],
            vec![],
            vec![vec![0x44; 32], vec![0x55; 32]],
            vec![7, 8],
            vec![(0, vec![vec![0x66; 32]]), (3, vec![])],
            Some(vec![("NOP_FEATURE_1".to_string(), "ACTIVE".to_string())]),
            None,
            Some("success".to_string()),
            Some(b"[]".to_vec()),
            Some(vec![(vec![0x77; 32], b"event-data".to_vec())]),
        )
        .unwrap()
    }

    #[test]
    fn test_roundtrip() {
        let bytes = sample();
        let (core, extra) = decode(&bytes).unwrap();
        assert_eq!(core.0, Some(vec![0x11; 32]));
        assert_eq!(core.1, "full");
        assert_eq!(core.2, vec![0x05, 0x00]);
        assert_eq!(core.3, vec![0x01]);
        assert_eq!(core.4, Some(vec![0x22; 32]));
        assert_eq!(core.5, vec![vec![0x33; 32], b"tx-non-grata".to_vec()]);
        assert_eq!(core.6, Vec::<Vec<u8>>::new());
        assert_eq!(core.7.len(), 2);
        assert_eq!(core.8, vec![7, 8]);
        assert_eq!(core.9, vec![(0, vec![vec![0x66; 32]]), (3, vec![])]);
        assert_eq!(
            extra.0,
            Some(vec![("NOP_FEATURE_1".to_string(), "ACTIVE".to_string())])
        );
        assert_eq!(extra.1, None);
        assert_eq!(extra.2, Some("success".to_string()));
        assert_eq!(extra.3, Some(b"[]".to_vec()));
        assert_eq!(
            extra.4,
            Some(vec![(vec![0x77; 32], b"event-data".to_vec())])
        );
    }

    #[test]
    fn test_minimal_record() {
        let bytes = metadata_to_bytes(
            None,
            "initial".to_string(),
            vec![0x01],
            vec![0x00],
            None,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let (core, extra) = decode(&bytes).unwrap();
        assert_eq!(core.0, None);
        assert_eq!(core.1, "initial");
        assert_eq!(extra.0, None);
        assert_eq!(extra.4, None);
    }

    #[test]
    fn test_rejects_bad_records() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[0xFF, 0x00]).is_none()); // wrong version
        let full = sample();
        for cut in 0..full.len() {
            assert!(
                decode(&full[..cut]).is_none(),
                "truncation at {cut} accepted"
            );
        }
        let mut extended = full.clone();
        extended.push(0x00);
        assert!(decode(&extended).is_none());
    }
}
