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

from hathor.transaction import Block, Transaction
from hathor.transaction.base_transaction import BaseTransaction
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.types import VertexId


class SimpleMemoryStorage:
    """
    Instances of this class simply facilitate storing some data in memory, specifically for pre-fetched verification
    dependencies.
    """
    __slots__ = ('_blocks', '_transactions',)

    def __init__(self) -> None:
        self._blocks: dict[VertexId, BaseTransaction] = {}
        self._transactions: dict[VertexId, BaseTransaction] = {}

    @property
    def _vertices(self) -> dict[VertexId, BaseTransaction]:
        """Blocks and Transactions together."""
        return {**self._blocks, **self._transactions}

    def get_block(self, block_id: VertexId) -> Block:
        """Return a block from the storage, throw if it's not found."""
        block = self._get_vertex(self._blocks, block_id)
        assert isinstance(block, Block)
        return block

    def get_transaction(self, tx_id: VertexId) -> Transaction:
        """Return a transaction from the storage, throw if it's not found."""
        tx = self._get_vertex(self._transactions, tx_id)
        assert isinstance(tx, Transaction)
        return tx

    @staticmethod
    def _get_vertex(storage: dict[VertexId, BaseTransaction], vertex_id: VertexId) -> BaseTransaction:
        """Return a vertex from a storage, throw if it's not found."""
        if vertex := storage.get(vertex_id):
            return vertex

        raise TransactionDoesNotExist(f'Vertex "{vertex_id.hex()}" does not exist in this SimpleMemoryStorage.')

    def get_parent_block(self, block: Block) -> Block:
        """Get the parent block of a block."""
        parent_hash = block.get_block_parent_hash()

        return self.get_block(parent_hash)

    def add_vertices_from_storage(self, storage: TransactionStorage, ids: list[VertexId]) -> None:
        """
        Add multiple vertices to this storage. It automatically fetches data from the provided TransactionStorage
        and a list of ids.
        """
        for vertex_id in ids:
            self.add_vertex_from_storage(storage, vertex_id)

    def add_vertex_from_storage(self, storage: TransactionStorage, vertex_id: VertexId) -> None:
        """
        Add a vertex to this storage. It automatically fetches data from the provided TransactionStorage and a list
        of ids.
        """
        if vertex_id in self._vertices:
            return

        vertex = storage.get_transaction(vertex_id)
        clone = vertex.clone(include_metadata=True, include_storage=False)

        if isinstance(vertex, Block):
            self._blocks[vertex_id] = clone
            return

        if isinstance(vertex, Transaction):
            self._transactions[vertex_id] = clone
            return

        raise NotImplementedError

    def get_vertex(self, vertex_id: VertexId) -> BaseTransaction:
        # TODO: Currently unused, will be implemented in a next PR.
        raise NotImplementedError

    def get_best_block_tips(self) -> list[VertexId]:
        # TODO: Currently unused, will be implemented in a next PR.
        raise NotImplementedError
