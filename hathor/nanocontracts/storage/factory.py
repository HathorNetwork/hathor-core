# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
