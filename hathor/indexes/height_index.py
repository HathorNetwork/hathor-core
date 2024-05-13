# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from abc import abstractmethod
from typing import NamedTuple, Optional

from hathor.indexes.base_index import BaseIndex
from hathor.indexes.scope import Scope
from hathor.transaction import BaseTransaction, Block
from hathor.types import VertexId

SCOPE = Scope(
    include_blocks=True,
    include_txs=False,
    include_voided=True,
)


class IndexEntry(NamedTuple):
    """Helper named tuple that implementations can use."""
    hash: bytes
    timestamp: int


class HeightInfo(NamedTuple):
    """Used by a few methods to represent a (height, hash) tuple."""
    height: int
    id: VertexId


class _AddToIndexItem(NamedTuple):
    height: int
    hash: bytes
    timestamp: int


class HeightIndex(BaseIndex):
    """Store the block hash for each given height
    """

    def get_genesis_block_entry(self) -> IndexEntry:
        """Return the index entry for the genesis block."""
        return IndexEntry(
            self._settings.GENESIS_BLOCK_HASH,
            self._settings.GENESIS_BLOCK_TIMESTAMP
        )

    def get_scope(self) -> Scope:
        return SCOPE

    def init_loop_step(self, tx: BaseTransaction) -> None:
        if not tx.is_block:
            return
        if tx.is_genesis:
            return
        assert isinstance(tx, Block)
        if tx.get_metadata().voided_by:
            return
        self.add_new(tx.get_height(), tx.hash, tx.timestamp)

    @abstractmethod
    def add_new(self, height: int, block_hash: bytes, timestamp: int) -> None:
        """Add a new block to the height index that **MUST NOT** result in a re-org"""
        raise NotImplementedError

    @abstractmethod
    def add_reorg(self, height: int, block_hash: bytes, timestamp: int) -> None:
        """Add a new block to the height index that **MIGHT** result in a re-org"""
        raise NotImplementedError

    @abstractmethod
    def get(self, height: int) -> Optional[bytes]:
        """ Return the block hash for the given height, or None if it is not set.
        """
        raise NotImplementedError

    @abstractmethod
    def get_tip(self) -> bytes:
        """ Return the best block hash, it returns the genesis when there is no other block
        """
        raise NotImplementedError

    @abstractmethod
    def get_height_tip(self) -> HeightInfo:
        """ Return the best block height and hash, it returns the genesis when there is no other block
        """
        raise NotImplementedError

    @abstractmethod
    def get_n_height_tips(self, n_blocks: int) -> list[HeightInfo]:
        """ Return the n best block height and hash list, it returns the genesis when there is no other block

        The returned list starts at the highest block and goes down in reverse height order.
        """
        raise NotImplementedError

    def update_new_chain(self, height: int, block: Block) -> None:
        """ When we have a new winner chain we must update all the height index
            until the first height with a common block
        """
        assert self.get(height) != block.hash

        block_height = height
        side_chain_block = block
        add_to_index: list[_AddToIndexItem] = []
        while self.get(block_height) != side_chain_block.hash:
            add_to_index.append(
                _AddToIndexItem(block_height, side_chain_block.hash, side_chain_block.timestamp)
            )

            side_chain_block = side_chain_block.get_block_parent()
            new_block_height = side_chain_block.get_height()
            assert new_block_height + 1 == block_height
            block_height = new_block_height

        # Reverse the data because I was adding in the array from the highest block
        reversed_add_to_index = reversed(add_to_index)

        for item in reversed_add_to_index:
            # Add it to the index
            self.add_reorg(item.height, item.hash, item.timestamp)
