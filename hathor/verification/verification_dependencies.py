#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from dataclasses import dataclass
from typing import TYPE_CHECKING

from typing_extensions import Self

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.reward_lock import get_spent_reward_locked_info
from hathor.reward_lock.reward_lock import get_minimum_best_height
from hathor.transaction import Block, Vertex
from hathor.transaction.transaction import RewardLockedInfo, TokenInfo, Transaction
from hathor.types import TokenUid, VertexId

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage


@dataclass(frozen=True, slots=True)
class VertexDependencies:
    """A dataclass of dependencies necessary for vertex verification."""
    parents: dict[VertexId, Vertex]

    @staticmethod
    def _get_parents_from_storage(vertex: Vertex, storage: 'TransactionStorage') -> dict[VertexId, Vertex]:
        return {vertex_id: storage.get_vertex(vertex_id) for vertex_id in vertex.parents}


@dataclass(frozen=True, slots=True)
class BasicBlockDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for basic block verification."""
    daa_deps: dict[VertexId, Block] | None

    @classmethod
    def create_from_storage(
        cls,
        block: Block,
        *,
        storage: 'TransactionStorage',
        daa: DifficultyAdjustmentAlgorithm,
        skip_weight_verification: bool,
    ) -> Self:
        """Create a basic block dependencies instance using dependencies from a storage."""
        parents = cls._get_parents_from_storage(block, storage)
        daa_deps: dict[VertexId, Block] | None = None

        if not block.is_genesis and not skip_weight_verification:
            daa_dep_ids = daa.get_block_dependencies(block, storage.get_parent_block)
            daa_deps = {vertex_id: storage.get_block(vertex_id) for vertex_id in daa_dep_ids}

        return cls(
            parents=parents,
            daa_deps=daa_deps,
        )

    def get_parent_block(self) -> Block:
        """Return the parent block of the block being verified."""
        parent_blocks = [vertex for vertex in self.parents.values() if isinstance(vertex, Block)]
        assert len(parent_blocks) == 1
        return parent_blocks[0]

    def get_parent_block_for_daa(self, block: Block) -> Block:
        """A method for getting parent blocks during DAA-related verification."""
        assert self.daa_deps is not None
        parent_hash = block.get_block_parent_hash()
        return self.daa_deps[parent_hash]


@dataclass(frozen=True, slots=True)
class BlockDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for block verification."""

    @classmethod
    def create_from_storage(cls, block: Block, *, storage: 'TransactionStorage') -> Self:
        """Create a block dependencies instance using dependencies from a storage."""
        parents = cls._get_parents_from_storage(block, storage)
        return cls(parents=parents)


@dataclass(frozen=True, slots=True)
class TransactionDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for transaction verification."""
    spent_txs: dict[VertexId, Vertex]
    token_info: dict[TokenUid, TokenInfo]
    reward_locked_info: RewardLockedInfo | None
    best_block_height: int

    @classmethod
    def create_from_storage(cls, tx: Transaction, storage: 'TransactionStorage') -> Self:
        """Create a transaction dependencies instance using dependencies from a storage."""
        parents = cls._get_parents_from_storage(tx, storage)
        spent_txs = {input_tx.tx_id: storage.get_vertex(input_tx.tx_id) for input_tx in tx.inputs}
        token_info = tx.get_complete_token_info()
        reward_locked_info = get_spent_reward_locked_info(tx, storage)
        best_block_height = get_minimum_best_height(storage)

        return cls(
            parents=parents,
            spent_txs=spent_txs,
            token_info=token_info,
            reward_locked_info=reward_locked_info,
            best_block_height=best_block_height,
        )
