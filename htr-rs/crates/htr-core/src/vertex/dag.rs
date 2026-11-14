// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub trait DagData {
    fn kind(&self) -> Kind;
    fn dag_parents(&self) -> SmallVec<[VertexId; 3]>;
    fn tx_parents(&self) -> SmallVec<[TransactionId; 2]>;
}

pub trait BlockDagData: DagData {
    fn block_parent(&self) -> Option<BlockId>;
}

pub trait TxDagData: DagData {}

// Single internal trait used to derive DagData without overlapping impls.
trait ImplDag {
    const KIND: Kind;
    fn impl_block_parent(&self) -> Option<BlockId>;
    fn impl_tx_parents(&self) -> SmallVec<[TransactionId; 2]>;
}

impl<T: ImplDag> DagData for T {
    fn kind(&self) -> Kind {
        T::KIND
    }
    fn dag_parents(&self) -> SmallVec<[VertexId; 3]> {
        let mut out = smallvec![];
        if let Some(bp) = self.impl_block_parent() {
            out.push(bp.0);
        }
        out.extend(self.impl_tx_parents().iter().map(|t| t.0));
        out
    }
    fn tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        self.impl_tx_parents()
    }
}

// Scope BlockDagData to blocks via concrete impls
impl BlockDagData for GenesisBlockData {
    fn block_parent(&self) -> Option<BlockId> {
        None
    }
}
impl BlockDagData for RegularBlockData {
    fn block_parent(&self) -> Option<BlockId> {
        Some(self.block_parent)
    }
}
impl BlockDagData for MergeMinedBlockData {
    fn block_parent(&self) -> Option<BlockId> {
        Some(self.block_parent)
    }
}
impl BlockDagData for PoaBlockData {
    fn block_parent(&self) -> Option<BlockId> {
        Some(self.block_parent)
    }
}

// Scope TxDagData to transactions via concrete impls
impl TxDagData for GenesisTransactionData {}
impl TxDagData for RegularTransactionData {}
impl TxDagData for TokenCreationTransactionData {}
impl TxDagData for OnChainBlueprintData {}

// Concrete ImplDag for each data type

// Blocks
impl ImplDag for GenesisBlockData {
    const KIND: Kind = Kind::RegularBlock;
    fn impl_block_parent(&self) -> Option<BlockId> {
        None
    }
    fn impl_tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        smallvec![]
    }
}

impl ImplDag for RegularBlockData {
    const KIND: Kind = Kind::RegularBlock;
    fn impl_block_parent(&self) -> Option<BlockId> {
        Some(self.block_parent)
    }
    fn impl_tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        smallvec![self.tx_parents[0], self.tx_parents[1]]
    }
}

impl ImplDag for MergeMinedBlockData {
    const KIND: Kind = Kind::MergeMinedBlock;
    fn impl_block_parent(&self) -> Option<BlockId> {
        Some(self.block_parent)
    }
    fn impl_tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        smallvec![self.tx_parents[0], self.tx_parents[1]]
    }
}

impl ImplDag for PoaBlockData {
    const KIND: Kind = Kind::PoaBlock;
    fn impl_block_parent(&self) -> Option<BlockId> {
        Some(self.block_parent)
    }
    fn impl_tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        smallvec![self.tx_parents[0], self.tx_parents[1]]
    }
}

// Transactions
impl ImplDag for GenesisTransactionData {
    const KIND: Kind = Kind::RegularTransaction;
    fn impl_block_parent(&self) -> Option<BlockId> {
        None
    }
    fn impl_tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        smallvec![]
    }
}

impl ImplDag for RegularTransactionData {
    const KIND: Kind = Kind::RegularTransaction;
    fn impl_block_parent(&self) -> Option<BlockId> {
        None
    }
    fn impl_tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        smallvec![self.tx_parents[0], self.tx_parents[1]]
    }
}

impl ImplDag for TokenCreationTransactionData {
    const KIND: Kind = Kind::TokenCreationTransaction;
    fn impl_block_parent(&self) -> Option<BlockId> {
        None
    }
    fn impl_tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        smallvec![self.tx_parents[0], self.tx_parents[1]]
    }
}

impl ImplDag for OnChainBlueprintData {
    const KIND: Kind = Kind::OnChainBlueprint;
    fn impl_block_parent(&self) -> Option<BlockId> {
        None
    }
    fn impl_tx_parents(&self) -> SmallVec<[TransactionId; 2]> {
        smallvec![self.tx_parents[0], self.tx_parents[1]]
    }
}
