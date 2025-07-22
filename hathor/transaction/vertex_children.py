#  Copyright 2025 Hathor Labs
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

from __future__ import annotations

import itertools
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterator, final

from structlog import get_logger
from typing_extensions import override

from hathor.indexes.rocksdb_utils import RocksDBIndexUtils
from hathor.storage import RocksDBStorage
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.transaction import Vertex

_VERTEX_CHILDREN_CF_NAME = b'vertex-children'

logger = get_logger()


class VertexChildrenService(ABC):
    __slots__ = ()

    @abstractmethod
    def get_children(self, parent: Vertex) -> VertexChildren:
        raise NotImplementedError

    @abstractmethod
    def add_child(self, parent: Vertex, child_id: VertexId) -> None:
        raise NotImplementedError

    @abstractmethod
    def remove_child(self, parent: Vertex, child_id: VertexId) -> None:
        raise NotImplementedError

    @abstractmethod
    def iter_children(self, parent: Vertex) -> Iterator[VertexId]:
        raise NotImplementedError

    @abstractmethod
    def contains_child(self, parent: Vertex, child_id: VertexId) -> bool:
        raise NotImplementedError


@final
class RocksDBVertexChildrenService(VertexChildrenService, RocksDBIndexUtils):
    __slots__ = ()

    def __init__(self, rocksdb_storage: RocksDBStorage) -> None:
        self.log = logger.new()
        super().__init__(rocksdb_storage.get_db(), _VERTEX_CHILDREN_CF_NAME)

    @override
    def get_children(self, parent: Vertex) -> VertexChildren:
        return VertexChildren(self, parent)

    @override
    def add_child(self, parent: Vertex, child_id: VertexId) -> None:
        key = self._to_key(parent, child_id)
        self.put(key, b'')

    @override
    def remove_child(self, parent: Vertex, child_id: VertexId) -> None:
        key = self._to_key(parent, child_id)
        self.delete(key)

    @override
    def iter_children(self, parent: Vertex) -> Iterator[VertexId]:
        it = self.iterkeys()
        it.seek(parent.hash)

        for _cf, key in it:
            parent_hash, child_hash = self._from_key(key)
            if parent_hash != parent.hash:
                break
            yield child_hash

    @override
    def contains_child(self, parent: Vertex, child_id: VertexId) -> bool:
        key = self._to_key(parent, child_id)
        return self.get_value(key) is not None

    @staticmethod
    def _to_key(parent: Vertex, child_id: VertexId) -> bytes:
        assert len(parent.hash) == 32
        assert len(child_id) == 32
        return parent.hash + child_id

    @staticmethod
    def _from_key(key: bytes) -> tuple[VertexId, VertexId]:
        assert len(key) == 64
        return key[:32], key[32:]


class VertexChildren:
    __slots__ = ('_service', '_parent')

    def __init__(self, service: VertexChildrenService, parent: Vertex) -> None:
        self._service = service
        self._parent = parent

    def __iter__(self) -> Iterator[VertexId]:
        return self._service.iter_children(self._parent)

    def __contains__(self, vertex_id: VertexId) -> bool:
        return self._service.contains_child(self._parent, vertex_id)

    def is_single(self) -> bool:
        return len(list(itertools.islice(self, 2))) == 1
