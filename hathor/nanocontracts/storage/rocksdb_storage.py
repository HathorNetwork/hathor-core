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

from typing import Optional

from hathor.nanocontracts.storage.backends import RocksDBNodeTrieStore
from hathor.nanocontracts.storage.base_storage import NCStorageFactory
from hathor.nanocontracts.storage.memory_storage import NCMemoryStorage
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor.types import VertexId


class NCRocksDBStorage(NCMemoryStorage):
    """RocksDB implementation of the storage. It is exactly the same as the memory but the trie store."""


class NCRocksDBStorageFactory(NCStorageFactory):
    """Factory to create a RocksDB storage for a contract.
    """

    def __init__(self, rocksdb_storage: RocksDBStorage) -> None:
        # This store keeps data from all contracts.
        self._store = RocksDBNodeTrieStore(rocksdb_storage)

    def __call__(self, nano_contract_id: VertexId, nc_root_id: Optional[bytes]) -> NCMemoryStorage:
        trie = self.get_trie(nc_root_id)
        return NCRocksDBStorage(trie=trie, nc_id=nano_contract_id)
