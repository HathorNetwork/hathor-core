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

from typing import TYPE_CHECKING

from hathor.nanocontracts.storage.backends import RocksDBNodeTrieStore
from hathor.nanocontracts.storage.block_storage import NCBlockStorage
# Re-export from hathorlib for backward compatibility
from hathorlib.nanocontracts.storage.factory import *  # noqa: F401,F403
from hathorlib.nanocontracts.storage.factory import NCStorageFactory  # noqa: F401

if TYPE_CHECKING:
    from hathor.storage import RocksDBStorage
    from hathor.transaction.block import Block


def get_block_storage_from_block(storage_factory: NCStorageFactory, block: Block) -> NCBlockStorage:
    """Return a block storage. If the block is genesis, it will return an empty block storage."""
    meta = block.get_metadata()
    if block.is_genesis:
        assert meta.nc_block_root_id is None
        return storage_factory.get_empty_block_storage()
    assert meta.nc_block_root_id is not None
    return storage_factory.get_block_storage(meta.nc_block_root_id)


class NCRocksDBStorageFactory(NCStorageFactory):
    """Factory to create a RocksDB storage for a contract.
    """

    def __init__(self, rocksdb_storage: 'RocksDBStorage') -> None:
        # This store keeps data from all contracts.
        self._store = RocksDBNodeTrieStore(rocksdb_storage)
