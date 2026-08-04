//! Static metadata: the canonical binary format (version 1) and the native computation of
//! transaction static metadata for the batch pipeline.
//!
//! Static metadata is write-once data derived from a vertex and its dependencies
//! (`hathor/transaction/static_metadata.py` is the reference). The format is defined here —
//! Rust is its future primary reader — and exposed to Python as plain codec functions; the
//! per-network DB is created fresh (no migration from the JSON format, per
//! `plans/rust-rocksdb-storage.md`).
//!
//! Layout (all integers big-endian):
//! ```text
//! [0] format version (1)
//! [1] kind: 0 = block, 1 = transaction
//! tx:    min_height u64 | closest_ancestor_block [u8; 32]
//! block: height u64 | min_height u64
//!        | n_bit_counts u16 | n * u32
//!        | n_features u16 | n * (name_len u8, name utf8, state_len u8, state utf8)
//! ```

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

const FORMAT_VERSION: u8 = 1;
pub const KIND_BLOCK: u8 = 0;
pub const KIND_TX: u8 = 1;
const HASH_SIZE: usize = 32;

/// A decoded static-metadata record.
pub(crate) enum StaticMeta {
    Block {
        height: u64,
        min_height: u64,
        bit_counts: Vec<u32>,
        feature_states: Vec<(String, String)>,
    },
    Tx {
        min_height: u64,
        closest_ancestor_block: Vec<u8>,
    },
}

pub(crate) fn encode(meta: &StaticMeta) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(FORMAT_VERSION);
    match meta {
        StaticMeta::Tx {
            min_height,
            closest_ancestor_block,
        } => {
            out.push(KIND_TX);
            out.extend_from_slice(&min_height.to_be_bytes());
            debug_assert_eq!(closest_ancestor_block.len(), HASH_SIZE);
            out.extend_from_slice(closest_ancestor_block);
        }
        StaticMeta::Block {
            height,
            min_height,
            bit_counts,
            feature_states,
        } => {
            out.push(KIND_BLOCK);
            out.extend_from_slice(&height.to_be_bytes());
            out.extend_from_slice(&min_height.to_be_bytes());
            out.extend_from_slice(&(bit_counts.len() as u16).to_be_bytes());
            for count in bit_counts {
                out.extend_from_slice(&count.to_be_bytes());
            }
            out.extend_from_slice(&(feature_states.len() as u16).to_be_bytes());
            for (name, state) in feature_states {
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
                out.push(state.len() as u8);
                out.extend_from_slice(state.as_bytes());
            }
        }
    }
    out
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
}

pub(crate) fn decode(data: &[u8]) -> Option<StaticMeta> {
    let mut r = Reader { data, pos: 0 };
    if r.u8()? != FORMAT_VERSION {
        return None;
    }
    let meta = match r.u8()? {
        KIND_TX => StaticMeta::Tx {
            min_height: r.u64()?,
            closest_ancestor_block: r.take(HASH_SIZE)?.to_vec(),
        },
        KIND_BLOCK => {
            let height = r.u64()?;
            let min_height = r.u64()?;
            let n_bits = r.u16()? as usize;
            let mut bit_counts = Vec::with_capacity(n_bits);
            for _ in 0..n_bits {
                let b = r.take(4)?;
                bit_counts.push(u32::from_be_bytes(
                    b.try_into().expect("take(4) returns 4 bytes"),
                ));
            }
            let n_features = r.u16()? as usize;
            let mut feature_states = Vec::with_capacity(n_features);
            for _ in 0..n_features {
                let name = r.string()?;
                let state = r.string()?;
                feature_states.push((name, state));
            }
            StaticMeta::Block {
                height,
                min_height,
                bit_counts,
                feature_states,
            }
        }
        _ => return None,
    };
    if r.pos != data.len() {
        return None;
    }
    Some(meta)
}

/// Serialize a block's static metadata (the canonical binary format).
#[pyfunction]
pub fn block_static_metadata_to_bytes(
    height: u64,
    min_height: u64,
    bit_counts: Vec<u32>,
    feature_states: Vec<(String, String)>,
) -> Vec<u8> {
    encode(&StaticMeta::Block {
        height,
        min_height,
        bit_counts,
        feature_states,
    })
}

/// Serialize a transaction's static metadata (the canonical binary format).
#[pyfunction]
pub fn tx_static_metadata_to_bytes(
    min_height: u64,
    closest_ancestor_block: Vec<u8>,
) -> PyResult<Vec<u8>> {
    if closest_ancestor_block.len() != HASH_SIZE {
        return Err(PyValueError::new_err(
            "closest_ancestor_block must be 32 bytes",
        ));
    }
    Ok(encode(&StaticMeta::Tx {
        min_height,
        closest_ancestor_block,
    }))
}

/// The unified decoded tuple handed to Python:
/// `(kind, height, min_height, bit_counts, feature_states, closest_ancestor_block)`.
type StaticMetaTuple = (u8, u64, u64, Vec<u32>, Vec<(String, String)>, Vec<u8>);

/// Parse a static-metadata record. Block-only/tx-only fields are zero/empty for the other
/// kind. A stored record that fails to parse is database corruption (or a format bug): it
/// raises instead of falling back.
#[pyfunction]
pub fn static_metadata_from_bytes(data: Vec<u8>) -> PyResult<StaticMetaTuple> {
    match decode(&data) {
        Some(StaticMeta::Tx {
            min_height,
            closest_ancestor_block,
        }) => Ok((
            KIND_TX,
            0,
            min_height,
            vec![],
            vec![],
            closest_ancestor_block,
        )),
        Some(StaticMeta::Block {
            height,
            min_height,
            bit_counts,
            feature_states,
        }) => Ok((
            KIND_BLOCK,
            height,
            min_height,
            bit_counts,
            feature_states,
            vec![],
        )),
        None => Err(PyValueError::new_err("invalid static metadata record")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_roundtrip() {
        let original = StaticMeta::Tx {
            min_height: 12345,
            closest_ancestor_block: vec![0xAB; 32],
        };
        let bytes = encode(&original);
        assert_eq!(bytes.len(), 2 + 8 + 32);
        let Some(StaticMeta::Tx {
            min_height,
            closest_ancestor_block,
        }) = decode(&bytes)
        else {
            panic!("expected tx record");
        };
        assert_eq!(min_height, 12345);
        assert_eq!(closest_ancestor_block, vec![0xAB; 32]);
    }

    #[test]
    fn test_block_roundtrip() {
        let original = StaticMeta::Block {
            height: 42,
            min_height: 40,
            bit_counts: vec![0, 3, 7, 1],
            feature_states: vec![
                ("NOP_FEATURE_1".to_string(), "ACTIVE".to_string()),
                ("NOP_FEATURE_2".to_string(), "DEFINED".to_string()),
            ],
        };
        let bytes = encode(&original);
        let Some(StaticMeta::Block {
            height,
            min_height,
            bit_counts,
            feature_states,
        }) = decode(&bytes)
        else {
            panic!("expected block record");
        };
        assert_eq!(height, 42);
        assert_eq!(min_height, 40);
        assert_eq!(bit_counts, vec![0, 3, 7, 1]);
        assert_eq!(feature_states.len(), 2);
        assert_eq!(
            feature_states[0],
            ("NOP_FEATURE_1".to_string(), "ACTIVE".to_string())
        );
    }

    #[test]
    fn test_block_empty_collections() {
        let bytes = encode(&StaticMeta::Block {
            height: 0,
            min_height: 0,
            bit_counts: vec![],
            feature_states: vec![],
        });
        assert!(matches!(decode(&bytes), Some(StaticMeta::Block { .. })));
    }

    #[test]
    fn test_rejects_bad_records() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[FORMAT_VERSION]).is_none());
        assert!(decode(&[0xFF, KIND_TX]).is_none()); // wrong version
        assert!(decode(&[FORMAT_VERSION, 0x07]).is_none()); // unknown kind
        // truncations
        let full = encode(&StaticMeta::Tx {
            min_height: 1,
            closest_ancestor_block: vec![0x01; 32],
        });
        for cut in 0..full.len() {
            assert!(
                decode(&full[..cut]).is_none(),
                "truncation at {cut} accepted"
            );
        }
        // trailing garbage
        let mut extended = full.clone();
        extended.push(0x00);
        assert!(decode(&extended).is_none());
    }
}
