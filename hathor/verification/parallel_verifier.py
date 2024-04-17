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

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.transaction import BaseTransaction, Block
from hathor.transaction.storage import TransactionStorage
from hathor.types import VertexId
from hathor.verification.verification_service import VerificationService


class ParallelVerifier:
    # __slots__ = ('_verification_service',)

    def __init__(
        self,
        *,
        tx_storage: TransactionStorage,
        verification_service: VerificationService,
        daa: DifficultyAdjustmentAlgorithm
    ) -> None:
        self._tx_storage = tx_storage
        self._daa = daa
        self._verification_service = verification_service
        self._processing_vertices: dict[VertexId, BaseTransaction] = {}

    async def validate_full(self, vertex: BaseTransaction, *, reject_locked_reward: bool) -> bool:
        self._processing_vertices[vertex.hash] = vertex

        result = await self._verification_service.validate_full_async(
            vertex,
            pre_fetched_deps=self._fetch_deps(vertex),
            reject_locked_reward=reject_locked_reward
        )
        del self._processing_vertices[vertex.hash]

        return result

    def _fetch_deps(self, vertex: BaseTransaction) -> dict[VertexId, BaseTransaction]:
        dep_ids = list(vertex.get_all_dependencies())
        if isinstance(vertex, Block):
            dep_ids += self._daa.get_block_dependencies(block=vertex)

        deps = {}
        for dep_id in dep_ids:
            dep = self._processing_vertices.get(dep_id) or self._tx_storage.get_transaction(dep_id)
            deps[dep_id] = dep

        return deps
