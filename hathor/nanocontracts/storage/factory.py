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

from abc import ABC
from typing import TYPE_CHECKING, Optional

from hathor.nanocontracts.storage.backends import MemoryNodeTrieStore, NodeTrieStore, RocksDBNodeTrieStore
from hathor.nanocontracts.storage.storage import NCStorage
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.nanocontracts.storage.patricia_trie import NodeId, PatriciaTrie
    from hathor.storage import RocksDBStorage


class NCStorageFactory(ABC):
    _store: 'NodeTrieStore'

    @staticmethod
    def bytes_to_node_id(node_id: Optional[bytes]) -> Optional['NodeId']:
        from hathor.nanocontracts.storage.patricia_trie import NodeId
        if node_id is None:
            return node_id
        return NodeId(node_id)

    def get_trie(self, root_id: Optional[bytes]) -> 'PatriciaTrie':
        """Return a PatriciaTrie object with a given root."""
        from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
        trie = PatriciaTrie(self._store, root_id=self.bytes_to_node_id(root_id))
        return trie

    def get_mempool_trie(self) -> 'PatriciaTrie':
        root_id = self.get_mempool_root_id()
        return self.get_trie(root_id)

    def get_mempool_root_id(self) -> bytes | None:
        try:
            return self._store[b'mempool']
        except KeyError:
            return None

    def save_mempool_root_id(self, root_id: bytes) -> None:
        self._store[b'mempool'] = root_id

    def __call__(self, nano_contract_id: VertexId, nc_root_id: Optional[bytes]) -> NCStorage:
        """Return a storage object for a given nano contract."""
        trie = self.get_trie(nc_root_id)
        return NCStorage(trie=trie, nc_id=nano_contract_id)


class NCMemoryStorageFactory(NCStorageFactory):
    """Factory to create a memory storage for a contract.

    As it is a memory storage, the factory keeps all contract stored data on
    its attribute `self.data`.
    """

    def __init__(self) -> None:
        # This attribute stores data from all contracts.
        self._store = MemoryNodeTrieStore()


class NCRocksDBStorageFactory(NCStorageFactory):
    """Factory to create a RocksDB storage for a contract.
    """

    def __init__(self, rocksdb_storage: 'RocksDBStorage') -> None:
        # This store keeps data from all contracts.
        self._store = RocksDBNodeTrieStore(rocksdb_storage)
