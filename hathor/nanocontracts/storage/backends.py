# Copyright 2023 Hathor Labs
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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from hathor.nanocontracts.storage.node_nc_type import NodeNCType
from hathor.serialization import Deserializer, Serializer
from hathor.storage.rocksdb_storage import RocksDBStorage

if TYPE_CHECKING:
    from hathor.nanocontracts.storage.patricia_trie import Node


class NodeTrieStore(ABC):
    @abstractmethod
    def __getitem__(self, key: bytes) -> Node:
        raise NotImplementedError

    @abstractmethod
    def __setitem__(self, key: bytes, item: Node) -> None:
        raise NotImplementedError

    @abstractmethod
    def __len__(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def __contains__(self, key: bytes) -> bool:
        raise NotImplementedError


class RocksDBNodeTrieStore(NodeTrieStore):
    _CF_NAME = b'nc-state'
    _KEY_LENGTH = b'length'

    def __init__(self, rocksdb_storage: RocksDBStorage) -> None:
        self._rocksdb_storage = rocksdb_storage
        self._db = self._rocksdb_storage.get_db()
        self._cf_key = self._rocksdb_storage.get_or_create_column_family(self._CF_NAME)
        self._node_nc_type = NodeNCType()

    def _serialize_node(self, node: Node, /) -> bytes:
        serializer = Serializer.build_bytes_serializer()
        self._node_nc_type.serialize(serializer, node)
        return bytes(serializer.finalize())

    def _deserialize_node(self, node_bytes: bytes, /) -> Node:
        deserializer = Deserializer.build_bytes_deserializer(node_bytes)
        node = self._node_nc_type.deserialize(deserializer)
        deserializer.finalize()
        return node

    def __getitem__(self, key: bytes) -> Node:
        item_bytes = self._db.get((self._cf_key, key))
        if item_bytes is None:
            raise KeyError(key.hex())
        return self._deserialize_node(item_bytes)

    def __setitem__(self, key: bytes, item: Node) -> None:
        item_bytes = self._serialize_node(item)
        self._db.put((self._cf_key, key), item_bytes)

    def __len__(self) -> int:
        it = self._db.iterkeys()
        it.seek_to_first()
        return sum(1 for _ in it)

    def __contains__(self, key: bytes) -> bool:
        return bool(self._db.get((self._cf_key, key)) is not None)
