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
from twisted.internet.task import deferLater
from typing_extensions import assert_never

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.reactor import ReactorProtocol, get_global_reactor
from hathor.reward_lock import get_spent_reward_locked_info
from hathor.transaction import Block, MergeMinedBlock, Transaction, TxVersion, Vertex
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
    __slots__ = (
        '_tx_storage',
        '_daa',
        '_verification_service',
        '_processing_vertices',
        '_rev_deps',
        '_waiting_vertices',
        '_reactor',
    )

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
        self._processing_vertices: dict[VertexId, Vertex] = {}
        self._rev_deps: defaultdict[VertexId, set[Vertex]] = defaultdict(set)
        self._waiting_vertices: dict[VertexId, Deferred[None]] = {}
        self._reactor = reactor

    async def validate_full(self, vertex: Vertex, *, reject_locked_reward: bool) -> bool:
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
            # self._reactor.callLater(0, self._finish, vertex.hash, deferred)
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
        todo = deque([(vertex_id, deferred)])
        while True:
            try:
                vertex_id, deferred = todo.popleft()
            except IndexError:
                break
            deferred.callback(None)
            for rev_dep in self._rev_deps[vertex_id]:
                if self._tx_storage.can_validate_full(rev_dep):
                    dep_deferred = self._waiting_vertices.pop(rev_dep.hash)
                    todo.append((rev_dep.hash, dep_deferred))
            del self._rev_deps[vertex_id]

    def is_processing(self, vertex_id: VertexId) -> bool:
        return vertex_id in self._processing_vertices

    def _get_verification_model(self, vertex: Vertex) -> VerificationModel:
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
        daa_deps = self._daa.get_block_dependencies(block, self._get_parent_block)

        basic_deps = BasicBlockDependencies(
            parents=parents,
            daa_deps=daa_deps,
        )

        deps = BlockDependencies(parents=parents)

        return basic_deps, deps

    def _get_tx_deps(self, tx: Transaction) -> TransactionDependencies:
        parents = {vertex_id: self._get_vertex(vertex_id) for vertex_id in tx.parents}
        spent_txs = {tx_input.tx_id: self._get_vertex(tx_input.tx_id) for tx_input in tx.inputs}
        token_info = tx.get_complete_token_info()

        # TODO: review this
        # get_best_block_tips is the only instance where we get information directly from the storage and not from our
        # processing vertices.
        reward_locked_info = get_spent_reward_locked_info(tx, self._get_vertex, self._tx_storage.get_best_block_tips)
        return TransactionDependencies(
            parents=parents,
            spent_txs=spent_txs,
            token_info=token_info,
            reward_locked_info=reward_locked_info,
            best_block_height=0,  # TODO
        )

    def _get_vertex(self, vertex_id: VertexId) -> Vertex:
        if vertex := self._processing_vertices.get(vertex_id):
            return vertex
        return self._tx_storage.get_vertex(vertex_id)

    def _get_parent_block(self, block: Block) -> Block:
        parent_hash = block.get_block_parent_hash()
        vertex = self._get_vertex(parent_hash)
        assert isinstance(vertex, Block)
        return vertex
