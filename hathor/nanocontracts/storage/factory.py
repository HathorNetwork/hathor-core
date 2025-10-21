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

from abc import ABC
from typing import TYPE_CHECKING, Optional

from hathor.nanocontracts.storage.backends import NodeTrieStore, RocksDBNodeTrieStore
from hathor.nanocontracts.storage.block_storage import NCBlockStorage

if TYPE_CHECKING:
    from hathor.nanocontracts.storage.patricia_trie import NodeId, PatriciaTrie
    from hathor.storage import RocksDBStorage
    from hathor.transaction.block import Block


class NCStorageFactory(ABC):
    _store: 'NodeTrieStore'

    @staticmethod
    def bytes_to_node_id(node_id: Optional[bytes]) -> Optional['NodeId']:
        from hathor.nanocontracts.storage.patricia_trie import NodeId
        if node_id is None:
            return node_id
        return NodeId(node_id)

    def _get_trie(self, root_id: Optional[bytes]) -> 'PatriciaTrie':
        """Return a PatriciaTrie object with a given root."""
        from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
        trie = PatriciaTrie(self._store, root_id=self.bytes_to_node_id(root_id))
        return trie

    def get_block_storage_from_block(self, block: Block) -> NCBlockStorage:
        """Return a block storage. If the block is genesis, it will return an empty block storage."""
        meta = block.get_metadata()
        if block.is_genesis:
            assert meta.nc_block_root_id is None
            return self.get_empty_block_storage()
        assert meta.nc_block_root_id is not None
        return self.get_block_storage(meta.nc_block_root_id)

    def get_block_storage(self, block_root_id: bytes) -> NCBlockStorage:
        """Return a non-empty block storage."""
        trie = self._get_trie(block_root_id)
        return NCBlockStorage(trie)

    def get_empty_block_storage(self) -> NCBlockStorage:
        """Create an empty block storage."""
        trie = self._get_trie(None)
        return NCBlockStorage(trie)


class NCRocksDBStorageFactory(NCStorageFactory):
    """Factory to create a RocksDB storage for a contract.
    """

    def __init__(self, rocksdb_storage: 'RocksDBStorage') -> None:
        # This store keeps data from all contracts.
        self._store = RocksDBNodeTrieStore(rocksdb_storage)
