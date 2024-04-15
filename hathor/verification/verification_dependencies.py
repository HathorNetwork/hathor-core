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

from typing_extensions import Self

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import BlockSignalingState, FeatureService
from hathor.feature_activation.model.feature_description import FeatureInfo
from hathor.transaction import BaseTransaction, Block, TransactionMetadata
from hathor.transaction.storage.simple_memory_storage import SimpleMemoryStorage
from hathor.transaction.transaction import TokenInfo, Transaction
from hathor.types import TokenUid, VertexId


@dataclass(frozen=True, slots=True)
class VertexDependencies:
    """A dataclass of dependencies necessary for vertex verification."""
    storage: SimpleMemoryStorage


@dataclass(frozen=True, slots=True)
class BasicBlockDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for basic block verification."""

    @classmethod
    def create(
        cls,
        block: Block,
        *,
        daa: DifficultyAdjustmentAlgorithm,
        skip_weight_verification: bool,
        pre_fetched_deps: dict[VertexId, BaseTransaction] | None = None
    ) -> Self:
        """Create a basic block dependencies instance."""
        assert block.storage is not None
        simple_storage = SimpleMemoryStorage()
        daa_deps = [] if skip_weight_verification else daa.get_block_dependencies(block)
        dep_ids = block.parents + daa_deps
        pre_fetched_deps = pre_fetched_deps or {}

        for dep_id in dep_ids:
            dep = pre_fetched_deps.get(dep_id) or block.storage.get_vertex(dep_id)
            simple_storage.add_vertex(dep)

        return cls(simple_storage)


@dataclass(frozen=True, slots=True)
class BlockDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for block verification."""
    metadata: TransactionMetadata
    signaling_state: BlockSignalingState
    feature_info: dict[Feature, FeatureInfo]

    @classmethod
    def create(
        cls,
        block: Block,
        *,
        feature_service: FeatureService,
        pre_fetched_deps: dict[VertexId, BaseTransaction] | None = None,
    ) -> Self:
        """Create a block dependencies instance."""
        assert block.storage is not None
        signaling_state = feature_service.is_signaling_mandatory_features(block)
        feature_info = feature_service.get_feature_info(block=block)
        simple_storage = SimpleMemoryStorage()
        pre_fetched_deps = pre_fetched_deps or {}

        for dep_id in block.parents:
            dep = pre_fetched_deps.get(dep_id) or block.storage.get_vertex(dep_id)
            simple_storage.add_vertex(dep)

        return cls(
            storage=simple_storage,
            metadata=block.get_metadata().clone(),
            signaling_state=signaling_state,
            feature_info=feature_info,
        )


@dataclass(frozen=True, slots=True)
class TransactionDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for transaction verification."""
    token_info: dict[TokenUid, TokenInfo]

    @classmethod
    def create(cls, tx: Transaction, *, pre_fetched_deps: dict[VertexId, BaseTransaction] | None = None) -> Self:
        """Create a transaction dependencies instance."""
        assert tx.storage is not None
        token_info = tx.get_complete_token_info()
        simple_storage = SimpleMemoryStorage()
        spent_txs = [tx_input.tx_id for tx_input in tx.inputs]
        deps = tx.parents + spent_txs
        pre_fetched_deps = pre_fetched_deps or {}

        simple_storage.set_best_block_tips_from_storage(tx.storage)

        for dep_id in deps:
            dep = pre_fetched_deps.get(dep_id) or tx.storage.get_vertex(dep_id)
            simple_storage.add_vertex(dep)

        return cls(
            storage=simple_storage,
            token_info=token_info
        )
