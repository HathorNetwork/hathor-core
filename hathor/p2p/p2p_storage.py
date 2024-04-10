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

from collections import defaultdict

from twisted.internet.defer import Deferred
from twisted.python.failure import Failure

from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.types import VertexId
from hathor.util import not_none


class P2PStorage:
    __slots__ = (
        '_tx_storage',
        '_mempool_tips_index',
        '_height_index',
        '_blocks_and_heights',
        '_transactions',
        '_blocks_by_height',
        '_children',
    )

    def __init__(self, *, tx_storage: TransactionStorage) -> None:
        assert tx_storage.indexes is not None
        assert tx_storage.indexes.mempool_tips is not None
        assert tx_storage.indexes.height is not None

        self._tx_storage = tx_storage
        self._mempool_tips_index = tx_storage.indexes.mempool_tips
        self._height_index = tx_storage.indexes.height

        self._blocks_and_heights: dict[VertexId, tuple[Block, int]] = {}
        self._blocks_by_height: dict[int, VertexId] = {}
        self._transactions: dict[VertexId, Transaction] = {}
        self._children: dict[VertexId, set[VertexId]] = defaultdict(set)

    @property
    def _blocks(self) -> dict[VertexId, Block]:
        return {vertex_id: block for vertex_id, (block, _) in self._blocks_and_heights.items()}

    @property
    def _vertices(self) -> dict[VertexId, BaseTransaction]:
        return {**self._blocks, **self._transactions}

    def add_new_vertex(self, vertex: BaseTransaction, deferred: Deferred[bool]) -> None:
        match vertex:
            case Block():
                height = self._calculate_height(vertex)
                self._blocks_and_heights[vertex.hash] = (vertex, height)
                self._blocks_by_height[height] = vertex.hash
            case Transaction():
                self._transactions[vertex.hash] = vertex

        for parent in vertex.parents:
            self._children[parent].add(vertex.hash)

        deferred.addBoth(self._remove_vertex, vertex)

    def _remove_vertex(self, deferred_result: bool | Failure, vertex: BaseTransaction) -> bool | Failure:
        match vertex:
            case Block():
                del self._blocks_and_heights[vertex.hash]
            case Transaction():
                del self._transactions[vertex.hash]

        self._blocks_by_height = {
            height: vertex_id
            for height, vertex_id in self._blocks_by_height.items()
            if vertex_id != vertex.hash
        }

        for children in self._children.values():
            children.discard(vertex.hash)

        return deferred_result

    def _calculate_height(self, block: Block) -> int:
        parent_hash = block.get_block_parent_hash()
        parent_and_height = self._blocks_and_heights.get(parent_hash)

        if not parent_and_height:
            return self._tx_storage.get_block(parent_hash).get_height() + 1

        _, parent_height = parent_and_height
        return parent_height + 1

    def get_mempool_tips(self) -> set[VertexId]:
        tips = self._mempool_tips_index.get()

        for tip in tips:
            if self._children[tip]:
                tips.remove(tip)

        for tx in self._transactions.values():
            if not self._children[tx.hash]:
                tips.add(tx.hash)

        return tips

    def get_best_block(self) -> Block:
        best_block = self._tx_storage.get_best_block()
        best_height = best_block.get_height()

        for block, height in self._blocks_and_heights.values():
            if height > best_height:
                best_block = block
                best_height = height

        return best_block

    def get_block_by_height(self, height: int) -> VertexId | None:
        storage_block = self._height_index.get(height)
        memory_block = self._blocks_by_height.get(height)

        if not memory_block:
            return storage_block

        assert storage_block is None
        return memory_block

    def partial_vertex_exists(self, vertex_id: VertexId) -> bool:
        """Return true if the vertex exists no matter its validation state."""
        with self._tx_storage.allow_partially_validated_context():
            exists_in_storage = self._tx_storage.transaction_exists(vertex_id)

        exists_in_memory = self._vertices.get(vertex_id) is not None

        if not exists_in_memory:
            return exists_in_storage

        assert not exists_in_storage
        return True

    def transaction_exists(self, vertex_id: VertexId) -> bool:
        exists_in_storage = self._tx_storage.transaction_exists(vertex_id)
        exists_in_memory = self._vertices.get(vertex_id) is not None

        if not exists_in_memory:
            return exists_in_storage

        assert not exists_in_storage
        return True

    def get_genesis(self, vertex_id: VertexId) -> BaseTransaction | None:
        return self._tx_storage.get_genesis(vertex_id)

    def compare_bytes_with_local_tx(self, tx: BaseTransaction) -> bool:
        memory_tx = self._vertices.get(tx.hash)

        if not memory_tx:
            return self._tx_storage.compare_bytes_with_local_tx(tx)

        return bytes(tx) == bytes(memory_tx)

    def get_vertex(self, vertex_id: VertexId) -> BaseTransaction:
        try:
            storage_vertex = self._tx_storage.get_vertex(vertex_id)
        except TransactionDoesNotExist:
            storage_vertex = None

        memory_vertex = self._vertices.get(vertex_id)

        if memory_vertex is None and storage_vertex is None:
            raise TransactionDoesNotExist(vertex_id)

        if not memory_vertex:
            return not_none(storage_vertex)

        assert storage_vertex is None
        return memory_vertex

    def get_block(self, block_id: VertexId) -> Block:
        try:
            storage_block = self._tx_storage.get_block(block_id)
        except TransactionDoesNotExist:
            storage_block = None

        memory_block = self._blocks.get(block_id)

        if memory_block is None and storage_block is None:
            raise TransactionDoesNotExist(block_id)

        if not memory_block:
            return not_none(storage_block)

        assert storage_block is None
        return memory_block

    def get_parent_block(self, block: Block) -> Block:
        try:
            storage_block = self._tx_storage.get_parent_block(block)
        except TransactionDoesNotExist:
            storage_block = None

        parent_id = block.get_block_parent_hash()
        memory_block = self._blocks.get(parent_id)

        if memory_block is None and storage_block is None:
            raise TransactionDoesNotExist(parent_id)

        if not memory_block:
            return not_none(storage_block)

        assert storage_block is None
        return memory_block

    def get_best_block_tips(self) -> list[VertexId]:
        tips = self._tx_storage.get_best_block_tips()

        for block in self._blocks.values():
            parent_block = self.get_parent_block(block)

            if parent_block.hash in tips:
                tips.remove(parent_block.hash)

            if not self._children[block.hash]:
                tips.append(block.hash)

        return tips

    def can_validate_full(self, vertex: BaseTransaction) -> bool:
        deps = vertex.get_all_dependencies()
        return all([self.transaction_exists(dep) for dep in deps])
