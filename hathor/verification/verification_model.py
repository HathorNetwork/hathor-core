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
from hathor.feature_activation.feature_service import BlockSignalingState, FeatureService
from hathor.transaction import Block
from hathor.transaction.storage.simple_memory_storage import SimpleMemoryStorage
from hathor.transaction.transaction import TokenInfo, Transaction
from hathor.types import TokenUid


@dataclass(frozen=True, slots=True)
class VertexDependencies:
    """A dataclass of dependencies necessary for vertex verification."""
    storage: SimpleMemoryStorage


@dataclass(frozen=True, slots=True)
class BlockDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for block verification."""
    signaling_state: BlockSignalingState

    @classmethod
    def create(cls, block: Block, daa: DifficultyAdjustmentAlgorithm, feature_service: FeatureService) -> Self:
        """Create a dependencies instance from a block and a DAA instance."""
        assert block.storage is not None
        signaling_state = feature_service.is_signaling_mandatory_features(block)
        simple_storage = SimpleMemoryStorage()
        daa_deps = daa.get_block_dependencies(block)
        deps = block.parents + daa_deps

        simple_storage.add_vertices_from_storage(block.storage, deps)
        simple_storage.add_vertex(block)

        return cls(
            storage=simple_storage,
            signaling_state=signaling_state
        )


@dataclass(frozen=True, slots=True)
class TransactionDependencies(VertexDependencies):
    """A dataclass of dependencies necessary for transaction verification."""
    token_info: dict[TokenUid, TokenInfo]

    @classmethod
    def create(cls, tx: Transaction) -> Self:
        """Create a dependencies instance from a transaction."""
        assert tx.storage is not None
        token_info = tx.get_complete_token_info()
        simple_storage = SimpleMemoryStorage()
        spent_txs = [tx_input.tx_id for tx_input in tx.inputs]
        deps = tx.parents + spent_txs

        simple_storage.add_vertices_from_storage(tx.storage, deps)
        simple_storage.set_best_block_tips_from_storage(tx.storage)

        return cls(
            storage=simple_storage,
            token_info=token_info
        )
