# Copyright 2025 Hathor Labs
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

"""Proxy storage backend for subprocess execution.

This module provides a proxy implementation of NodeTrieStore that requests
trie data from the main process via queue-based DataRequest/DataResponse
pattern. This eliminates the need for the subprocess to access RocksDB
directly, avoiding locking and blocking issues.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from hathor.nanocontracts.storage.backends import NodeTrieStore
from hathor.nanocontracts.storage.factory import NCStorageFactory
from hathor.nanocontracts.storage.node_nc_type import NodeNCType
from hathor.serialization import Deserializer, Serializer

if TYPE_CHECKING:
    from hathor.nanocontracts.storage.patricia_trie import Node


class ProxyNodeTrieStore(NodeTrieStore):
    """NodeTrieStore that proxies reads to main process via queue.

    This store is used in the subprocess worker to access trie nodes
    without directly opening RocksDB. All read operations are sent to
    the main process which has the actual RocksDB access.

    Write operations are cached locally and the serialized nodes can be
    retrieved later for the main process to commit.
    """

    def __init__(self, request_func: Callable[[str, bytes], bytes | None]) -> None:
        """Initialize the proxy store.

        Args:
            request_func: Function to request data from main process.
                         Signature: (request_type: str, request_data: bytes) -> bytes | None
        """
        self._request_func = request_func
        self._cache: dict[bytes, bytes] = {}  # Local write cache (serialized nodes)
        self._node_nc_type = NodeNCType()

    def _serialize_node(self, node: 'Node') -> bytes:
        """Serialize a node to bytes."""
        serializer = Serializer.build_bytes_serializer()
        self._node_nc_type.serialize(serializer, node)
        return bytes(serializer.finalize())

    def _deserialize_node(self, node_bytes: bytes) -> 'Node':
        """Deserialize a node from bytes."""
        deserializer = Deserializer.build_bytes_deserializer(node_bytes)
        node = self._node_nc_type.deserialize(deserializer)
        deserializer.finalize()
        return node

    def __getitem__(self, key: bytes) -> 'Node':
        """Get a node by key.

        First checks the local cache (for writes during this execution),
        then requests from the main process.
        """
        # Check local cache first (for writes during this execution)
        if key in self._cache:
            return self._deserialize_node(self._cache[key])

        # Request from main process
        node_bytes = self._request_func('trie_get', key)
        if node_bytes is None:
            raise KeyError(key.hex())
        return self._deserialize_node(node_bytes)

    def __setitem__(self, key: bytes, item: 'Node') -> None:
        """Store a node in the local cache.

        Nodes are cached locally and can be retrieved via get_cached_writes()
        for the main process to commit to RocksDB.
        """
        self._cache[key] = self._serialize_node(item)

    def __contains__(self, key: bytes) -> bool:
        """Check if a key exists."""
        if key in self._cache:
            return True
        result = self._request_func('trie_contains', key)
        return result == b'\x01'

    def __len__(self) -> int:
        """Return the number of nodes.

        Not supported in proxy mode as it would require iterating
        over the entire database in the main process.
        """
        raise NotImplementedError("len() not supported in proxy mode")

    def get_cached_writes(self) -> dict[bytes, bytes]:
        """Return all cached writes for main process to commit.

        Returns:
            Dictionary mapping trie keys to serialized node bytes.
        """
        return self._cache.copy()


class NCProxyStorageFactory(NCStorageFactory):
    """Factory that creates proxy storages for subprocess execution.

    This factory creates PatriciaTrie instances backed by a ProxyNodeTrieStore,
    which requests trie data from the main process instead of accessing
    RocksDB directly.
    """

    _store: ProxyNodeTrieStore  # Override type from base class

    def __init__(self, request_func: Callable[[str, bytes], bytes | None]) -> None:
        """Initialize the proxy storage factory.

        Args:
            request_func: Function to request data from main process.
                         Signature: (request_type: str, request_data: bytes) -> bytes | None
        """
        self._store = ProxyNodeTrieStore(request_func)

    def get_proxy_store(self) -> ProxyNodeTrieStore:
        """Return the proxy store for accessing cached writes."""
        return self._store
