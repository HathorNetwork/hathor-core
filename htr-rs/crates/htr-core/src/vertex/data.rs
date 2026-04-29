// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::num::NonZero;
use typed_floats::PositiveFinite;

#[repr(transparent)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    derive_more::Deref,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
    derive_more::Display,
    derive_more::FromStr,
    Serialize,
    Deserialize,
)]
#[display("{_0}")]
#[serde(transparent)]
pub struct VertexId(pub Hash32);
forward_try_from_slice!(VertexId, Hash32);

#[repr(transparent)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    derive_more::Deref,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
    derive_more::Display,
    derive_more::FromStr,
    Serialize,
    Deserialize,
)]
#[display("{_0}")]
#[serde(transparent)]
pub struct BlockId(pub VertexId);
forward_try_from_slice!(BlockId, VertexId);

#[repr(transparent)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    derive_more::Deref,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
    derive_more::Display,
    derive_more::FromStr,
    Serialize,
    Deserialize,
)]
#[display("{_0}")]
#[serde(transparent)]
pub struct TransactionId(pub VertexId);
forward_try_from_slice!(TransactionId, VertexId);

#[repr(transparent)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    derive_more::Deref,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
    derive_more::Display,
    derive_more::FromStr,
    Serialize,
    Deserialize,
)]
#[display("{_0}")]
#[serde(transparent)]
pub struct TokenUid(pub Hash32);
forward_try_from_slice!(TokenUid, Hash32);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, derive_more::TryFrom)]
#[try_from(repr)]
#[repr(u8)]
pub enum Kind {
    RegularBlock = 0,
    RegularTransaction = 1,
    TokenCreationTransaction = 2,
    MergeMinedBlock = 3,
    // #[deprecated]
    // NanoContract = 4,
    PoaBlock = 5,
    OnChainBlueprint = 6,
}

impl Kind {
    pub const fn is_transaction(self) -> bool {
        match self {
            Kind::RegularBlock => false,
            Kind::RegularTransaction => true,
            Kind::TokenCreationTransaction => true,
            Kind::MergeMinedBlock => false,
            // #[allow(deprecated)]
            // Kind::NanoContract => true,
            Kind::PoaBlock => false,
            Kind::OnChainBlueprint => true,
        }
    }
    pub const fn is_block(self) -> bool {
        !self.is_transaction()
    }
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default, derive_more::TryFrom,
)]
#[try_from(repr)]
#[repr(u8)]
pub enum TokenKind {
    Native = 0,
    #[default]
    Deposit = 1,
    Fee = 2,
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default, derive_more::TryFrom,
)]
#[try_from(repr)]
#[repr(u8)]
pub enum OcbKind {
    #[default]
    PythonZlib = 1,
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SignalBits(pub u8);

#[derive(Copy, Debug, Clone, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Timestamp(pub u32);

pub type Weight = PositiveFinite<f64>;

pub type OutputValue = NonZero<u64>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxOutput {
    pub value: OutputValue,
    pub token_data: u8,
    pub script: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxInput {
    pub tx_id: TransactionId,
    pub index: u8,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GenesisBlockData {
    pub outputs: Vec<TxOutput>,
    pub weight: Weight,
    pub timestamp: Timestamp,
    pub nonce: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegularBlockData {
    pub signal_bits: SignalBits,
    pub outputs: Vec<TxOutput>,
    pub weight: Weight,
    pub timestamp: Timestamp,
    pub block_parent: BlockId,
    pub tx_parents: [TransactionId; 2],
    pub data: Bytes,
    pub nonce: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuxPow {
    pub header_head: [u8; 36],
    pub coinbase_head: Bytes,
    pub coinbase_tail: Bytes,
    pub merkle_path: Vec<Hash32>,
    pub header_tail: [u8; 12],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MergeMinedBlockData {
    pub signal_bits: SignalBits,
    pub outputs: Vec<TxOutput>,
    pub weight: Weight,
    pub timestamp: Timestamp,
    pub block_parent: BlockId,
    pub tx_parents: [TransactionId; 2],
    pub data: Bytes,
    pub aux_pow: AuxPow,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoaBlockData {
    pub signal_bits: SignalBits,
    pub weight: Weight,
    pub timestamp: Timestamp,
    pub block_parent: BlockId,
    pub tx_parents: [TransactionId; 2],
    pub data: Bytes,
    pub signer_id: [u8; 2],
    pub signature: Bytes,
    pub nonce: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GenesisTransactionData {
    pub outputs: Vec<TxOutput>,
    pub weight: Weight,
    pub timestamp: Timestamp,
    pub nonce: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegularTransactionData {
    pub signal_bits: SignalBits,
    pub tokens: Vec<TokenUid>,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub weight: Weight,
    pub timestamp: Timestamp,
    pub tx_parents: [TransactionId; 2],
    pub nonce: u32,
    pub headers: Vec<AnyHeader>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenCreationTransactionData {
    pub signal_bits: SignalBits,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub token_kind: TokenKind,
    // XXX: enough inline capacity for typical case, uses heap otherwise, max-len not enforced by
    // these types
    pub name: SmallString<[u8; MAX_TOKEN_NAME_LEN]>,
    pub symbol: SmallString<[u8; MAX_TOKEN_SYMBOL_LEN]>,
    pub weight: Weight,
    pub timestamp: Timestamp,
    pub tx_parents: [TransactionId; 2],
    pub nonce: u32,
    pub headers: Vec<AnyHeader>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OnChainBlueprintData {
    pub signal_bits: SignalBits,
    pub tokens: Vec<TokenUid>,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub ocb_kind: OcbKind,
    pub code: Bytes,
    pub nc_pubkey: Bytes,
    pub nc_signature: Bytes,
    pub weight: Weight,
    pub timestamp: Timestamp,
    pub tx_parents: [TransactionId; 2],
    pub nonce: u32,
    pub headers: Vec<AnyHeader>,
}
