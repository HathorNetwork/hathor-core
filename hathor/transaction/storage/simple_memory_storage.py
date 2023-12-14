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

from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.types import VertexId


class SimpleMemoryStorage:
    __slots__ = ('_blocks', '_transactions',)

    def __init__(self) -> None:
        self._blocks: dict[VertexId, Block] = {}
        self._transactions: dict[VertexId, Transaction] = {}

    @property
    def _vertices(self) -> dict[VertexId, BaseTransaction]:
        return {**self._blocks, **self._transactions}

    def get_block(self, block_id: VertexId) -> Block:
        if block := self._blocks.get(block_id):
            return block

        raise TransactionDoesNotExist(f'Block "{block_id.hex()}" does not exist in this SimpleMemoryStorage.')

    def get_transaction(self, tx_id: VertexId) -> Transaction:
        if tx := self._transactions.get(tx_id):
            return tx

        raise TransactionDoesNotExist(f'Transaction "{tx_id.hex()}" does not exist in this SimpleMemoryStorage.')

    def get_parent_block(self, block: Block) -> Block:
        parent_hash = block.get_block_parent_hash()

        return self.get_block(parent_hash)

    def add_vertices_from_storage(self, storage: TransactionStorage, ids: list[VertexId]) -> None:
        for vertex_id in ids:
            self.add_vertex_from_storage(storage, vertex_id)

    def add_vertex_from_storage(self, storage: TransactionStorage, vertex_id: VertexId) -> None:
        if vertex_id in self._vertices:
            return

        vertex = storage.get_transaction(vertex_id)

        match vertex:
            case Block():
                self._blocks[vertex_id] = vertex
            case Transaction():
                self._transactions[vertex_id] = vertex
            case _:
                raise NotImplementedError
