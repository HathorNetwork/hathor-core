#  Copyright 2024 Hathor Labs
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

from collections import defaultdict, deque

from twisted.internet.defer import Deferred
from typing_extensions import assert_never

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import BlockIsSignaling
from hathor.reactor import ReactorProtocol
from hathor.reward_lock import get_spent_reward_locked_info
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction, TxVersion
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.validation_state import ValidationState
from hathor.types import VertexId
from hathor.verification.verification_dependencies import (
    BasicBlockDependencies,
    BlockDependencies,
    TransactionDependencies,
)
from hathor.verification.verification_model import (
    VerificationBlock,
    VerificationMergeMinedBlock,
    VerificationModel,
    VerificationTokenCreationTransaction,
    VerificationTransaction,
)
from hathor.verification.verification_service import VerificationService


class ParallelVerifier:
    # __slots__ = ('_verification_service',)

    def __init__(
        self,
        *,
        tx_storage: TransactionStorage,
        verification_service: VerificationService,
        daa: DifficultyAdjustmentAlgorithm,
        reactor: ReactorProtocol,
    ) -> None:
        self._tx_storage = tx_storage
        self._daa = daa
        self._verification_service = verification_service
        self._processing_vertices: dict[VertexId, BaseTransaction] = {}
        self._rev_deps: defaultdict[VertexId, set[BaseTransaction]] = defaultdict(set)
        self._waiting_vertices: dict[VertexId, Deferred[None]] = {}
        self._queue: deque[tuple[VertexId, Deferred[None]]] = deque()
        self._reactor = reactor

    async def validate_full(self, vertex: BaseTransaction, *, reject_locked_reward: bool) -> bool:
        self._processing_vertices[vertex.hash] = vertex

        verification_model = self._get_verification_model(vertex)
        result = await self._verification_service.validate_full_async(
            verification_model,
            reject_locked_reward=reject_locked_reward
        )

        dep_ids = vertex.get_all_dependencies()
        missing_deps = []
        for dep_id in dep_ids:
            try:
                self._tx_storage.get_vertex(dep_id)
            except TransactionDoesNotExist:
                missing_deps.append(dep_id)

        deferred: Deferred[None] = Deferred()

        if not missing_deps:
            self._reactor.callLater(0, self._finish, vertex.hash, deferred)
        else:
            for dep_id in missing_deps:
                self._rev_deps[dep_id].add(vertex)

            self._waiting_vertices[vertex.hash] = deferred

        await deferred
        if result:
            vertex.set_validation(ValidationState.FULL)
        del self._processing_vertices[vertex.hash]
        return result

    def _finish(self, vertex_id: VertexId, deferred: Deferred[None]) -> None:
        deferred.callback(None)
        for rev_dep in self._rev_deps[vertex_id]:
            if self._tx_storage.can_validate_full(rev_dep):
                dep_deferred = self._waiting_vertices.pop(rev_dep.hash)
                self._finish(rev_dep.hash, dep_deferred)
        del self._rev_deps[vertex_id]

    def is_processing(self, vertex_id: VertexId) -> bool:
        return vertex_id in self._processing_vertices

    def _get_verification_model(self, vertex: BaseTransaction) -> VerificationModel:
        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                basic_deps, deps = self._get_block_deps(vertex)
                return VerificationBlock(
                    vertex=vertex,
                    basic_deps=basic_deps,
                    deps=deps,
                )

            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                basic_deps, deps = self._get_block_deps(vertex)
                return VerificationMergeMinedBlock(
                    vertex=vertex,
                    basic_deps=basic_deps,
                    deps=deps,
                )

            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                return VerificationTransaction(
                    vertex=vertex,
                    basic_deps=None,
                    deps=self._get_tx_deps(vertex),
                )

            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                return VerificationTokenCreationTransaction(
                    vertex=vertex,
                    basic_deps=None,
                    deps=self._get_tx_deps(vertex),
                )

            case _:
                assert_never(vertex.version)

    def _get_block_deps(self, block: Block) -> tuple[BasicBlockDependencies, BlockDependencies]:
        parents = {vertex_id: self._get_vertex(vertex_id) for vertex_id in block.parents}
        parent_block_hash = block.get_block_parent_hash()
        parent_block = self._get_vertex(parent_block_hash)
        assert isinstance(parent_block, Block)
        parent_height = self._get_block_height(parent_block)
        daa_dep_ids = self._daa.get_block_dependencies(block, parent_height, self._get_parent_block)
        daa_deps = {}
        for dep_id in daa_dep_ids:
            vertex = self._get_vertex(dep_id)
            assert isinstance(vertex, Block)
            daa_deps[dep_id] = vertex

        basic_deps = BasicBlockDependencies(
            parents=parents,
            daa_deps=daa_deps,
            parent_height=parent_height,
        )

        deps = BlockDependencies(
            parents=parents,
            height=self._get_block_height(block),
            min_height=self._get_block_min_height(block),
            signaling_state=BlockIsSignaling(),  # TODO
            feature_info={},  # TODO
        )

        return basic_deps, deps

    def _get_tx_deps(self, tx: Transaction) -> TransactionDependencies:
        parents = {vertex_id: self._get_vertex(vertex_id) for vertex_id in tx.parents}
        spent_txs = {tx_input.tx_id: self._get_vertex(tx_input.tx_id) for tx_input in tx.inputs}
        token_info = tx.get_complete_token_info()
        # TODO: We should also get tips from self._processing_vertices
        tips_heights = self._tx_storage.get_tips_heights()
        reward_locked_info = get_spent_reward_locked_info(spent_txs.values(), tips_heights)
        return TransactionDependencies(
            parents=parents,
            spent_txs=spent_txs,
            token_info=token_info,
            reward_locked_info=reward_locked_info,
        )

    def _get_vertex(self, vertex_id: VertexId) -> BaseTransaction:
        return self._processing_vertices.get(vertex_id) or self._tx_storage.get_vertex(vertex_id)

    def _get_parent_block(self, block: Block) -> Block:
        parent_hash = block.get_block_parent_hash()
        vertex = self._get_vertex(parent_hash)
        assert isinstance(vertex, Block)
        return vertex

    def _get_block_height(self, block: Block) -> int:
        # TODO
        return 0
        if block.is_genesis:
            return 0

        parent_hash = block.get_block_parent_hash()
        if parent := self._processing_vertices.get(parent_hash):
            assert isinstance(parent, Block)
            return self._get_block_height(parent) + 1

        parent = self._tx_storage.get_block(parent_hash)
        return parent.get_height() + 1

    def _get_block_min_height(self, block: Block) -> int:
        # TODO
        return 0
