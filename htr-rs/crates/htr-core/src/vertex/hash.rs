// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0
/*!
# Vertex Hash Specification

This document defines how the 32‑byte hash (VertexId) of any Vertex (aka BaseTransaction) is computed. A Vertex may be
one of:

- Regular block (`Block`)
- Merge‑mined block (`MergeMinedBlock`)
- PoA block (`PoaBlock`)
- Regular transaction (`Transaction`)
- Token creation transaction (`TokenCreationTransaction`)
- On‑chain blueprint (if enabled)

The rules below are normative and reflect the implementation in this repository.

## Overview

- Vertex hash is SHA‑256d (double SHA‑256) over a fixed preimage composed of:
  1) `H_funds` = SHA‑256 of the funds serialization
  2) `H_graph_headers` = SHA‑256 of the graph serialization concatenated with the headers serialization
  3) `NONCE[16]` = the `nonce` field encoded as 16‑byte unsigned big‑endian
- Final VertexId bytes are the byte‑reversal of the SHA‑256 of the inner SHA‑256 digest (i.e. reversed SHA‑256d).

In pseudocode:

```text
H_funds = SHA256(funds_struct(V))
H_graph_headers = SHA256(graph_struct(V) || headers_struct(V))
inner = SHA256(H_funds || H_graph_headers || INT_TO_BE(V.nonce, 16))
vertex_id = REVERSE_BYTES(SHA256(inner))  # 32 bytes
```

Notes:

- The 16‑byte hashing nonce is used for all vertex types, regardless of their on‑wire serialization size.
- When shown as hex (e.g., `hash_hex`), the VertexId is the big‑endian representation of `vertex_id` above.

## Component Serializations

All multi‑byte integers in the serializations below use network byte order (big‑endian). Field sizes and layouts are
fixed unless otherwise stated.

### Funds serialization (`funds_struct`)

Common leading fields for all vertex types are `signal_bits` (1 byte) and `version` (1 byte).

- Block (`Block`, `PoaBlock`, `MergeMinedBlock`):
  - Format: `!BBB` → `signal_bits (1)`, `version (1)`, `outputs_len (1)`
  - Followed by `outputs_len` serialized `TxOutput`s.
  - For PoA blocks, `outputs_len` must be 0.

- Transaction‑family (`Transaction`, `TokenCreationTransaction`, `OnChainBlueprint`):
  - Format: `!BBBBB` → `signal_bits (1)`, `version (1)`, `tokens_len (1)`, `inputs_len (1)`, `outputs_len (1)`
  - Followed by `tokens_len` token UIDs (each 32 bytes), then `inputs_len` serialized `TxInput`s, then `outputs_len`
    serialized `TxOutput`s (in that order).

### Graph serialization (`graph_struct`)

Common prefix for all vertex types:

- Format: `!dIB` → `weight (8‑byte IEEE‑754 double)`, `timestamp (4‑byte uint)`, `parents_len (1)`
- Followed by `parents_len` parent hashes, each 32 bytes (`VertexId`). The first parent of any block is its block parent.

Block extensions:

- Regular block (`Block`) and merge‑mined/PoA derivatives append:
  - `data_len (1)` and then `data (data_len bytes)`

PoA block extensions:

- After the block `data` fields above, append:
  - `signer_id` (fixed length, `SIGNER_ID_LEN` bytes)
  - `signature_len (1)` and `signature (signature_len bytes)`

Transaction‑family has no extra graph fields beyond the common prefix.

### Headers serialization (`headers_struct`)

- Zero or more typed headers serialized back‑to‑back, each starting with a 1‑byte header ID (e.g., Nano header 0x10,
  Fee header 0x11) followed by the header’s own payload. The maximum number of headers is currently 2.

### Nonce for hashing vs. serialization

- Hashing nonce size is always 16 bytes (`HASH_NONCE_SIZE = 16`). The integer `nonce` is encoded as 16‑byte unsigned
  big‑endian and appended to the hashing preimage.
- Serialization nonce size differs by type (`SERIALIZATION_NONCE_SIZE`):
  - Transactions: 4 bytes
  - Blocks (and derivatives, including PoA and merge‑mined): 16 bytes
- PoA blocks set `nonce = 0` but still use the 16‑byte zero nonce in the hash preimage.

## Mining Header and Base Hash

The “mining header without nonce” is the 64‑byte concatenation `H_funds || H_graph_headers`.

- `mining_header = SHA256(funds_struct) || SHA256(graph_struct || headers_struct)` → 64 bytes
- This is used for miners/stratum to avoid re‑hashing variable‑length pieces.

For blocks, the “mining base hash” is defined as:

```text
mining_base_hash = REVERSE_BYTES(SHA256(SHA256(mining_header)))
```

This value is used by merge‑mining and external miners as the base block hash before including the nonce or external
proof‑of‑work data.

## Final Hash by Vertex Type

- Regular block (`Block`) and PoA block (`PoaBlock`):
  - VertexId is computed exactly as in the Overview (double SHA‑256 over the 64‑byte mining header plus 16‑byte nonce).

- Regular transaction (`Transaction`), token creation, on‑chain blueprint:
  - VertexId is computed exactly as in the Overview. Transactions serialize a 4‑byte nonce on‑wire, but hashing still
    uses a 16‑byte big‑endian nonce value in the preimage.

- Merge‑mined block (`MergeMinedBlock`):
  - VertexId is derived from the embedded Bitcoin AuxPoW data. Let `B = mining_base_hash` of the Hathor block (as above).
  - Compute the coinbase transaction hash: `H_cb = SHA256d(coinbase_head || B || coinbase_tail)` (bytes reversed).
  - Build the Bitcoin merkle root by folding `H_cb` with the provided merkle path; the merkle root bytes fed into the
    header are in little‑endian (i.e., reverse the standard merkle construction output to match Bitcoin wire format).
  - The final VertexId is the Bitcoin header double‑SHA‑256 of `header_head || merkle_root || header_tail`, with the
    result bytes reversed (consistent with the VertexId endianness convention).

## Determinism and Endianness

- All lengths and counters in the serializations use big‑endian network order (`struct.pack` with `!`). Parent and token
  hashes are raw 32‑byte values in the VertexId byte order defined here.
- VertexId is always the reversed bytes of the final SHA‑256 digest (big‑endian when rendered as hex).

## Rationale

- Splitting the preimage into two fixed 32‑byte sub‑hashes (`H_funds`, `H_graph_headers`) yields a constant 64‑byte
  mining header regardless of variable‑length components, enabling efficient mining and stable PoW input size.
- Using a 16‑byte hashing nonce for all vertex types keeps mining logic uniform between blocks and transactions.

*/

use super::*;
use crate::crypto::{DigestContext, sha256};

fn get_funds_hash<H: HashableData>(h: &H) -> Hash32 {
    let mut buf = BytesMut::new();
    h.write_funds(&mut buf);
    sha256(buf.freeze())
}

fn get_graph_hash<H: HashableData>(h: &H) -> Hash32 {
    let mut buf = BytesMut::new();
    h.write_graph(&mut buf);
    sha256(buf.freeze())
}

fn get_nonce_bytes<H: HashableData>(h: &H) -> Bytes {
    let mut buf = BytesMut::new();
    h.write_nonce(&mut buf);
    buf.freeze()
}

pub trait HashableData: Sized {
    fn write_funds<B: BufMut>(&self, buf: &mut B);
    fn write_graph<B: BufMut>(&self, buf: &mut B);
    fn write_nonce<B: BufMut>(&self, buf: &mut B);
    fn compute_hash(&self) -> Hash32 {
        let mut ctx = DigestContext::new_sha256();
        ctx.update(get_funds_hash(self));
        ctx.update(get_graph_hash(self));
        ctx.update(get_nonce_bytes(self));
        sha256(ctx.finalize()).reversed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        const_hex::decode(s).expect("hex")
    }

    #[test]
    fn hash_genesis_block_sample() {
        let hex = "000001ffffffe8b789180000001976a914a584cf48b161e4a49223ed220df30037ab740e0088ac40350000000000005e0be1000000000000000000000000000000000c9ba0";
        let raw = hex_to_bytes(hex);
        let AnyBlockData::Genesis(g) = decode_any_block_data(raw.as_slice()).expect("parse") else {
            panic!("genesis")
        };
        let vid = g.compute_hash();
        assert_eq!(
            vid.to_string(),
            "0000033139d08176d1051fb3a272c3610457f0c7f686afbe0afe3d37f966db85"
        );
    }

    #[test]
    fn hash_regular_block_sample() {
        let hex = "0000010000190000001976a914b677a202c8ccc20ff765a789ffe8b7930d33642588ac40350000000000005f2a45f9030000033139d08176d1051fb3a272c3610457f0c7f686afbe0afe3d37f966db8500e161a6b0bee1781ea9300680913fb76fd0fac4acab527cd9626cc1514abdc900975897028ceb037307327c953f5e7ad4d3f42402d71bd3d11ecb63ac39f01a6235393839383938633636663764663465623938616138363536303834613364372d64653332623364303839326434656366616534306165343335396231323536632d616661663032303735626231343731323831656636313130643333333061326100000000000000000000000200217e76";
        let raw = hex_to_bytes(hex);
        let AnyBlockData::Regular(b) = decode_any_block_data(raw.as_slice()).expect("parse") else {
            panic!("regular")
        };
        let vid = b.compute_hash();
        assert_eq!(
            vid.to_string(),
            "000003ae3be32b9df13157a27b77cf8e5fed3c20ad309a843002a10c5430c9cc"
        );
    }
}
