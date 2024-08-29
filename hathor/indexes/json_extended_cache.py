# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Optional

from hathor.indexes.base_index import BaseIndex
from hathor.indexes.scope import Scope
from hathor.transaction import BaseTransaction
from hathor.types import VertexId
from hathor.util import json_dumpb

if TYPE_CHECKING:  # pragma: no cover
    from hathor.transaction.storage import TransactionStorage

SCOPE = Scope(
    include_blocks=True,
    include_txs=True,
    include_voided=False,
)


class JsonExtendedCache(BaseIndex):
    """Store the block hash for each given height
    """

    def get_scope(self) -> Scope:
        return SCOPE

    def init_loop_step(self, tx: BaseTransaction) -> None:
        pass

    def get_with_cache(self, vertex_id: VertexId, tx_storage: TransactionStorage) -> Optional[bytes]:
        """ Return the serialized .to_json_extended() value, it's only recalculated if there's no cached value.
        """
        cached_value = self.get(vertex_id)
        if cached_value is not None:
            return cached_value
        vertex = tx_storage.get_vertex(vertex_id)
        value = json_dumpb(vertex.to_json_extended())
        self.set(vertex_id, value)
        return value

    @abstractmethod
    def get(self, vertex_id: VertexId) -> Optional[bytes]:
        """ Return the serialized cache of the .to_json_extended() value, returns None if there's no value in cache
        """
        raise NotImplementedError

    @abstractmethod
    def set(self, vertex_id: VertexId, data: bytes) -> None:
        """ Update the serialized cached value of the .to_json_extended().
        """
        raise NotImplementedError

    @abstractmethod
    def invalidate(self, vertex_id: VertexId) -> None:
        """ Invalidate the cached value of .to_json_extended() of the vertex with the given id.
        """
        raise NotImplementedError
