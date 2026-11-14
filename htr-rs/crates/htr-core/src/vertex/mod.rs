// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0
/*!
## Conventions

- Byte order: big‑endian unless stated otherwise.
- Types
    - u8/u16/u32: 1/2/4‑byte unsigned integers, big‑endian.
    - f64: 8‑byte IEEE‑754 float, big‑endian.
    - bytes[N]: exactly N bytes.
    - varlen(n): a length-prefixed blob; the length field size is indicated where used.
    - sha256d(x): sha256(sha256(x)).
- VertexId and Hashes
    - All vertex/tx/block IDs are 32 bytes (big‑endian presentation). Parents are encoded as raw 32‑byte IDs in this format.
- Sections (order on the wire)
    1. Funds section (aka “funds_struct”)
    2. Graph section (aka “graph_struct”)
    3. Nonce section
    4. Headers section (zero or more headers)

## Output-Value Integer Encoding

- A transaction output value is encoded as either 4 or 8 bytes:
  - If 0 < value ≤ 2^31−1: write a 4‑byte signed positive integer.
  - If 2^31 ≤ value ≤ 2^63: write an 8‑byte signed negative integer equal to −value.
- Decoding rule: peek first byte; if negative, read 8 and negate; else read 4. Zero is invalid on-chain (strict mode). Maximum is 2^63.
- This encoding is also used for Nano-Contract action amounts.

## Inputs and Outputs

- TxInput
  - tx_id: bytes[32]
  - index: u8
  - data_len: u16
  - data: bytes[data_len]
- TxOutput
  - value: output-value (4 or 8 bytes as above)
  - token_data: u8
    - bit7 (0x80): authority flag (1 = authority output)
    - bits0..6: token index (0..127)
      - Index 0 = native HTR (not present in tokens list)
      - Index k>0 = tokens[k−1] in the tokens list below
    - For authority outputs, value’s low bits indicate authorities:
      - 0x01 = mint, 0x02 = melt, 0x03 = both
  - script_len: u16
  - script: bytes[script_len] (node‑enforced max typical: 1024)

## Headers container

- After the nonce, zero or more headers may appear. Each is prefixed by a 1‑byte header ID. Unknown headers must be rejected.
- Known header:
  - NANO_HEADER (id 0x10)
    - nc_id: bytes[32]
    - nc_seqnum: unsigned LEB128 (max 8 bytes)
    - method_len: u8
    - method: ASCII bytes[method_len]
    - args_len: u16
    - args: bytes[args_len]
    - actions_count: u8
      - For each action:
        - type: u8 (1=DEPOSIT, 2=WITHDRAWAL, 3=GRANT_AUTHORITY, 4=ACQUIRE_AUTHORITY)
        - token_index: u8
        - amount: output‑value
    - nc_address: bytes[25] (address)
    - nc_script_len: unsigned LEB128 (max 2 bytes)
    - nc_script: bytes[nc_script_len]
    - Sighash contribution: same as above but with nc_script_len=0 and no nc_script.

## Hashing

- Mining header: H = sha256(funds_struct) || sha256(graph_struct || headers_struct) (64 bytes total).
- Nonce for hashing: 16‑byte big‑endian nonce value (even if serialized with fewer bytes on the wire).
- Vertex hash: reverse(sha256d(H || nonce16)).
- Merge‑mined blocks: vertex hash is derived from the embedded Bitcoin header (see below).

## REGULAR_TRANSACTION (kind=1)

### Funds

- signal_bits:u8, kind:u8 (=1), tokens_len:u8, inputs_len:u8, outputs_len:u8
- tokens: tokens_len × bytes[32] (non‑HTR token UIDs)
- inputs: inputs_len × TxInput
- outputs: outputs_len × TxOutput

### Graph

- weight:f64, timestamp:u32 (Unix seconds), parents_len:u8, parents: parents_len × bytes[32]

### Nonce

- u32 (4‑byte big‑endian)

### Headers

- zero or more headers (e.g., NANO_HEADER)

## TOKEN_CREATION_TRANSACTION (kind=2)

### Funds

- signal_bits:u8, kind:u8 (=2), inputs_len:u8, outputs_len:u8
- inputs, outputs (as above)
- token_info:
  - token_kind:u8 (0=NATIVE, 1=DEPOSIT, 2=FEE; creation normally uses 1)
  - name_len:u8, name: UTF‑8 bytes[name_len] (typical max 30)
  - symbol_len:u8, symbol: UTF‑8 bytes[symbol_len] (typical max 5)

### Graph, Nonce, Headers

- Same as Regular Transaction.
- The created token UID equals this transaction’s hash; it is implicitly index 1 for outputs that reference it.

## REGULAR_BLOCK (kind=0)

### Funds

- signal_bits:u8, kind:u8 (=0), outputs_len:u8
- outputs: outputs_len × TxOutput (block subsidy/fees)

### Graph

- weight:f64, timestamp:u32, parents_len:u8, parents: parents_len × bytes[32]
- data_len:u8, data: bytes[data_len] (node‑enforced typical max: 100)

### Nonce

- bytes[16]

### Headers

- zero or more headers

## MERGE_MINED_BLOCK (kind=3)

### Funds

- Same as Regular Block.

### Graph

- Same as Regular Block.

### Nonce (AuxPoW blob; replaces the 16‑byte nonce)

- AuxPow bytes, layout:
  - header_head: bytes[36] (first 36 bytes of Bitcoin header)
  - coinbase_head: varbytes (Bitcoin varint length + data)
  - coinbase_tail: varbytes
  - merkle_path_count: varint (LE); then merkle_path_count × bytes[32] (each link)
    - Limit: merkle_path_count ≤ 100
  - header_tail: bytes[12] (last 12 bytes of Bitcoin header)
- All varint/varbytes here use Bitcoin’s little‑endian varint format.

### Headers

- zero or more headers

### Hash

- Let base = sha256d(get_mining_header_without_nonce) where get_mining_header_without_nonce is the 64‑byte mining header above.
- Vertex hash = Bitcoin double‑SHA of the constructed Bitcoin header derived via the AuxPoW path using base as coinbase commit (per the field semantics above). This supersedes the generic sha256d rule.

## POA_BLOCK (kind=5)

### Funds

- Same as Regular Block (but must have zero outputs).

### Graph

- weight:f64, timestamp:u32, parents_len:u8, parents..., data_len:u8, data...
- signer_id: bytes[2] (consensus.poa signer ID)
- signature_len: u8 (max 100), signature: bytes[signature_len]

### Nonce

- bytes[16] (present but not part of the signed message)
  Headers
- zero or more headers

###   Hash

- Block hash follows the generic rule (includes PoA fields in graph_struct).

### Signature verification
- Signed message = sha256(funds_struct || (Regular Block graph_struct without PoA fields) || nonce16)
- Signature: ECDSA‑P256/SHA‑256 over the above. signer_id identifies the signer’s public key.

## ON_CHAIN_BLUEPRINT (kind=6)

### Funds

- Regular Transaction funds (no tokens list implied unless present), then append:
  - ocb_kind:u8 (currently 1)
  - code_len:u32, code: bytes[code_len] where:
    - code[0]: code_kind:u8 (1=PYTHON_ZLIB)
    - code[1..]: compressed code bytes (zlib)
    - Typical limits: compressed ≤ 24,000 bytes; decompressed ≤ 240,000 bytes
  - nc_pubkey_len:u8, nc_pubkey: bytes[nc_pubkey_len] (compressed EC pubkey)
  - nc_signature_len:u8, nc_signature: bytes[nc_signature_len] (ECDSA‑P256/SHA‑256 over sighash_all, see below)

### Graph, Nonce, Headers

- Graph, parents, nonce (u32), and optional headers as in Regular Transaction.
  Sighash for signature
- sighash_all = serialization of [funds (including code and pubkey, but with nc_signature_len=0 and empty signature), outputs, inputs, tokens, and headers’ sighash_bytes], then sha256(sighash_all).

## Graph Section (all vertices)

- weight:f64
- timestamp:u32 (Unix seconds)
- parents_len:u8
- parents: parents_len × bytes[32]
- For blocks only: data_len:u8, data: bytes[data_len]
- PoA blocks: append signer_id and signature after data (see above)

## Nonce Section (all vertices)

- Regular transactions: u32
- Regular/PoA blocks: bytes[16]
- Merge‑mined blocks: AuxPoW blob (see above)

## Limits and Notes

- Parents count, inputs/outputs counts: u8 (0..255).
- Scripts and input data are length‑prefixed; nodes enforce application‑level limits (typical: script ≤ 1024, block data ≤ 100).
- The tokens list contains only non‑HTR token UIDs (32‑byte each). HTR is always token index 0 and has no UID entry in the list.
- All multi‑byte integers and floats are big‑endian except AuxPoW’s Bitcoin varints/fields (which use Bitcoin’s LE formats).
- Unknown header IDs must be rejected. NANO_HEADER may appear only on transactions; blocks typically have no headers.
*/

use crate::common::{Address, Hash32};
use crate::utils::forward_try_from_slice;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use smallstr::SmallString;
use smallvec::{SmallVec, smallvec};
use std::array::TryFromSliceError;
use thiserror::Error;

mod dag;
mod data;
mod decode;
mod encode;
mod hash;
mod header;

pub use self::data::{
    AuxPow, BlockId, GenesisBlockData, GenesisTransactionData, Kind, MergeMinedBlockData, OcbKind,
    OnChainBlueprintData, OutputValue, PoaBlockData, RegularBlockData, RegularTransactionData,
    SignalBits, Timestamp, TokenCreationTransactionData, TokenKind, TokenUid, TransactionId,
    TxInput, TxOutput, VertexId, Weight,
};

pub use self::dag::{BlockDagData, DagData, TxDagData};
pub use self::decode::{
    decode_any_block_data, decode_any_transaction_data, decode_any_vertex_data,
};
pub use self::encode::{
    encode_any_block_data, encode_any_transaction_data, encode_any_vertex_data,
};
pub use self::hash::HashableData;
pub use self::header::{AnyHeader, FeeHeader, HeaderKind, NanoHeader};

const MAX_MERKLE_PATH_LEN: usize = 20;
const MAX_TOKEN_NAME_LEN: usize = 30;
const MAX_TOKEN_SYMBOL_LEN: usize = 5;

pub trait VertexData: DagData + HashableData {}

/// automatically implemented for very type that is both DagData and HashableData
impl<T: DagData + HashableData> VertexData for T {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, derive_more::From)]
pub enum AnyBlockData {
    Genesis(GenesisBlockData),
    Regular(RegularBlockData),
    MergeMined(MergeMinedBlockData),
    // XXX: we might want to handle PoA blocks differently, since they are only available on special cases
    Poa(PoaBlockData),
}

impl DagData for AnyBlockData {
    fn kind(&self) -> Kind {
        match self {
            AnyBlockData::Genesis(g) => g.kind(),
            AnyBlockData::Regular(r) => r.kind(),
            AnyBlockData::MergeMined(m) => m.kind(),
            AnyBlockData::Poa(p) => p.kind(),
        }
    }

    fn dag_parents(&self) -> SmallVec<[VertexId; 3]> {
        match self {
            AnyBlockData::Genesis(g) => g.dag_parents(),
            AnyBlockData::Regular(r) => r.dag_parents(),
            AnyBlockData::MergeMined(m) => m.dag_parents(),
            AnyBlockData::Poa(p) => p.dag_parents(),
        }
    }

    fn tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        match self {
            AnyBlockData::Genesis(g) => g.tx_parents(),
            AnyBlockData::Regular(r) => r.tx_parents(),
            AnyBlockData::MergeMined(m) => m.tx_parents(),
            AnyBlockData::Poa(p) => p.tx_parents(),
        }
    }
}

impl BlockDagData for AnyBlockData {
    fn block_parent(&self) -> Option<BlockId> {
        match self {
            AnyBlockData::Genesis(g) => g.block_parent(),
            AnyBlockData::Regular(r) => r.block_parent(),
            AnyBlockData::MergeMined(m) => m.block_parent(),
            AnyBlockData::Poa(p) => p.block_parent(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, derive_more::From)]
pub enum AnyTransactionData {
    Genesis(GenesisTransactionData),
    Regular(RegularTransactionData),
    TokenCreation(TokenCreationTransactionData),
    OnChainBlueprint(OnChainBlueprintData),
}

impl DagData for AnyTransactionData {
    fn kind(&self) -> Kind {
        match self {
            AnyTransactionData::Genesis(t) => t.kind(),
            AnyTransactionData::Regular(t) => t.kind(),
            AnyTransactionData::TokenCreation(t) => t.kind(),
            AnyTransactionData::OnChainBlueprint(t) => t.kind(),
        }
    }

    fn dag_parents(&self) -> SmallVec<[VertexId; 3]> {
        match self {
            AnyTransactionData::Genesis(t) => t.dag_parents(),
            AnyTransactionData::Regular(t) => t.dag_parents(),
            AnyTransactionData::TokenCreation(t) => t.dag_parents(),
            AnyTransactionData::OnChainBlueprint(t) => t.dag_parents(),
        }
    }

    fn tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        match self {
            AnyTransactionData::Genesis(t) => t.tx_parents(),
            AnyTransactionData::Regular(t) => t.tx_parents(),
            AnyTransactionData::TokenCreation(t) => t.tx_parents(),
            AnyTransactionData::OnChainBlueprint(t) => t.tx_parents(),
        }
    }
}

impl TxDagData for AnyTransactionData {}

#[derive(Clone, Debug, PartialEq, Eq, Hash, derive_more::From)]
pub enum AnyVertexData {
    Block(AnyBlockData),
    Transaction(AnyTransactionData),
}

impl DagData for AnyVertexData {
    fn kind(&self) -> Kind {
        match self {
            AnyVertexData::Block(b) => b.kind(),
            AnyVertexData::Transaction(t) => t.kind(),
        }
    }

    fn dag_parents(&self) -> SmallVec<[VertexId; 3]> {
        match self {
            AnyVertexData::Block(b) => b.dag_parents(),
            AnyVertexData::Transaction(t) => t.dag_parents(),
        }
    }

    fn tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        match self {
            AnyVertexData::Block(b) => b.tx_parents(),
            AnyVertexData::Transaction(t) => t.tx_parents(),
        }
    }
}

impl From<GenesisBlockData> for AnyVertexData {
    fn from(data: GenesisBlockData) -> Self {
        AnyVertexData::Block(data.into())
    }
}

impl From<RegularBlockData> for AnyVertexData {
    fn from(data: RegularBlockData) -> Self {
        AnyVertexData::Block(data.into())
    }
}

impl From<MergeMinedBlockData> for AnyVertexData {
    fn from(data: MergeMinedBlockData) -> Self {
        AnyVertexData::Block(data.into())
    }
}

impl From<PoaBlockData> for AnyVertexData {
    fn from(data: PoaBlockData) -> Self {
        AnyVertexData::Block(data.into())
    }
}

impl From<GenesisTransactionData> for AnyVertexData {
    fn from(data: GenesisTransactionData) -> Self {
        AnyVertexData::Transaction(data.into())
    }
}

impl From<RegularTransactionData> for AnyVertexData {
    fn from(data: RegularTransactionData) -> Self {
        AnyVertexData::Transaction(data.into())
    }
}

impl From<TokenCreationTransactionData> for AnyVertexData {
    fn from(data: TokenCreationTransactionData) -> Self {
        AnyVertexData::Transaction(data.into())
    }
}

impl From<OnChainBlueprintData> for AnyVertexData {
    fn from(data: OnChainBlueprintData) -> Self {
        AnyVertexData::Transaction(data.into())
    }
}
