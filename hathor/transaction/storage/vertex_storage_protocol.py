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

from abc import abstractmethod
from typing import Protocol

from hathor.transaction import BaseTransaction, Block
from hathor.types import VertexId


class VertexStorageProtocol(Protocol):
    """
    This Protocol currently represents a subset of TransactionStorage methods. Its main use case is for verification
    methods that can receive a RocksDB storage or an ephemeral simple memory storage.

    Therefore, objects returned by this protocol may or may not have an `object.storage` pointer set.
    """

    @abstractmethod
    def get_vertex(self, vertex_id: VertexId) -> BaseTransaction:
        """Return a vertex from the storage."""
        raise NotImplementedError

    @abstractmethod
    def get_block(self, block_id: VertexId) -> Block:
        """Return a block from the storage."""
        raise NotImplementedError

    @abstractmethod
    def get_parent_block(self, block: Block) -> Block:
        """Get the parent block of a block."""
        raise NotImplementedError

    @abstractmethod
    def get_best_block_hash(self) -> VertexId:
        """Return a list of blocks that are heads in a best chain."""
        raise NotImplementedError
