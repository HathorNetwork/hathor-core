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

from abc import ABC, abstractmethod
from dataclasses import dataclass

from typing_extensions import Self

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import BlockSignalingState, FeatureService
from hathor.feature_activation.model.feature_description import FeatureInfo
from hathor.reward_lock import get_spent_reward_locked_info
from hathor.transaction import BaseTransaction, Block
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.transaction import RewardLockedInfo, TokenInfo, Transaction
from hathor.types import TokenUid, VertexId
from hathor.util import not_none


@dataclass(frozen=True, slots=True)
class VertexDependencies(ABC):
    """A dataclass of dependencies necessary for vertex verification."""
    parents: dict[VertexId, BaseTransaction]

    @abstractmethod
    def clone(self) -> Self:
        raise NotImplementedError

    @staticmethod
    def _clone_vertices(vertices: dict[VertexId, BaseTransaction]) -> dict[VertexId, BaseTransaction]:
        return {
            vertex_id: vertex.clone(include_storage=False, include_metadata=False)
            for vertex_id, vertex in vertices.items()
        }


@dataclass(frozen=True, slots=True)
class BasicBlockDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for basic block verification."""
    daa_deps: dict[VertexId, Block] | None
    parent_height: int | None

    @classmethod
    def create_from_storage(
        cls,
        block: Block,
        *,
        storage: TransactionStorage,
        daa: DifficultyAdjustmentAlgorithm,
        skip_weight_verification: bool,
    ) -> Self:
        """Create a basic block dependencies instance."""
        parents = {vertex_id: storage.get_vertex(vertex_id) for vertex_id in block.parents}
        daa_deps: dict[VertexId, Block] | None = None
        parent_height: int | None = None

        if not block.is_genesis:
            parent_height = block.get_block_parent().get_height()

            if not skip_weight_verification:
                daa_dep_ids = daa.get_block_dependencies(block, parent_height, storage.get_parent_block)
                daa_deps = {vertex_id: storage.get_block(vertex_id) for vertex_id in daa_dep_ids}

        return cls(
            parents=parents,
            daa_deps=daa_deps,
            parent_height=parent_height,
        )

    def get_parent_block(self) -> Block:
        parent_blocks = [vertex for vertex in self.parents.values() if isinstance(vertex, Block)]
        assert len(parent_blocks) == 1
        return parent_blocks[0]

    def get_parent_height(self) -> int:
        assert self.parent_height is not None
        return self.parent_height

    def get_daa_parent_block(self, block: Block) -> Block:
        assert self.daa_deps is not None
        parent_hash = block.get_block_parent_hash()
        return self.daa_deps[parent_hash]

    def clone(self) -> Self:
        return BasicBlockDependencies(
            parents=self._clone_vertices(self.parents),
            daa_deps=self._clone_vertices(self.daa_deps) if self.daa_deps else None,
            parent_height=self.parent_height,
        )


@dataclass(frozen=True, slots=True)
class BlockDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for block verification."""
    height: int
    min_height: int
    signaling_state: BlockSignalingState
    feature_info: dict[Feature, FeatureInfo]

    @classmethod
    def create_from_storage(
        cls,
        block: Block,
        *,
        storage: TransactionStorage,
        feature_service: FeatureService
    ) -> Self:
        """Create a block dependencies instance."""
        parents = {vertex_id: storage.get_vertex(vertex_id) for vertex_id in block.parents}
        signaling_state = feature_service.is_signaling_mandatory_features(block)
        feature_info = feature_service.get_feature_info(block=block)
        meta = block.get_metadata()

        return cls(
            parents=parents,
            height=not_none(meta.height),
            min_height=not_none(meta.min_height),
            signaling_state=signaling_state,
            feature_info=feature_info,
        )

    def clone(self) -> Self:
        return BlockDependencies(
            parents=self._clone_vertices(self.parents),
            height=self.height,
            min_height=self.min_height,
            signaling_state=self.signaling_state,
            feature_info=self.feature_info,
        )


@dataclass(frozen=True, slots=True)
class TransactionDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for transaction verification."""
    spent_txs: dict[VertexId, BaseTransaction]
    token_info: dict[TokenUid, TokenInfo]
    reward_locked_info: RewardLockedInfo | None

    @classmethod
    def create_from_storage(cls, tx: Transaction, storage: TransactionStorage) -> Self:
        """Create a transaction dependencies instance."""
        parents = {vertex_id: storage.get_vertex(vertex_id) for vertex_id in tx.parents}
        spent_txs = storage.get_spent_txs(tx)
        tips_heights = storage.get_tips_heights()
        reward_locked_info = get_spent_reward_locked_info(spent_txs.values(), tips_heights)
        token_info = tx.get_complete_token_info()

        return cls(
            parents=parents,
            spent_txs=spent_txs,
            token_info=token_info,
            reward_locked_info=reward_locked_info,
        )

    def clone(self) -> Self:
        return TransactionDependencies(
            parents=self._clone_vertices(self.parents),
            spent_txs=self._clone_vertices(self.spent_txs),
            token_info=self.token_info,
            reward_locked_info=self.reward_locked_info,
        )
