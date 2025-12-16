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

from typing import TYPE_CHECKING

from hathor.sysctl.sysctl import Sysctl, signal_handler_safe

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage


class StorageSysctl(Sysctl):
    def __init__(self, tx_storage: 'TransactionStorage') -> None:
        super().__init__()

        self.tx_storage = tx_storage
        self.register(
            'rocksdb.flush',
            None,
            self.set_rocksdb_flush,
        )
        self.register(
            'rocksdb.wal_stats',
            self.get_rocksdb_wal_stats,
            None,
        )

    @signal_handler_safe
    def set_rocksdb_flush(self) -> None:
        """Manually trigger a RocksDB flush to persist memtables to disk.
        
        This forces RocksDB to write all in-memory data (memtables) to SST files on disk.
        Useful for ensuring data persistence or freeing up memory.
        """
        # Check if we have a RocksDB storage
        from hathor.transaction.storage import TransactionRocksDBStorage
        
        # Get the underlying storage
        storage = self.tx_storage
        
        # If it's a cache storage, get the underlying store
        if hasattr(storage, 'store'):
            storage = storage.store
        
        # Only flush if it's a RocksDB storage
        if isinstance(storage, TransactionRocksDBStorage):
            db = storage._db
            # Flush all column families
            # The flush method is available in python-rocksdb
            try:
                db.flush()
                self.log.info('rocksdb flush completed successfully')
            except AttributeError:
                self.log.error('rocksdb flush method not available in this version of python-rocksdb')
            except Exception as e:
                self.log.error('error during rocksdb flush', error=str(e))
        else:
            self.log.warn('rocksdb flush command called but storage is not RocksDB', 
                         storage_type=type(storage).__name__)

    def get_rocksdb_wal_stats(self) -> dict[str, float | dict[str, float]]:
        """Get WAL (Write-Ahead Log) statistics for RocksDB.
        
        Returns statistics including:
        - total_wal_size: Total size of all WAL files in bytes
        - wal_size_per_cf: Dictionary with WAL size per column family in bytes
        
        This is useful to verify that flush operations are working correctly.
        """
        from hathor.transaction.storage import TransactionRocksDBStorage
        
        # Get the underlying storage
        storage = self.tx_storage
        
        # If it's a cache storage, get the underlying store
        if hasattr(storage, 'store'):
            storage = storage.store
        
        # Only get stats if it's a RocksDB storage
        if isinstance(storage, TransactionRocksDBStorage):
            db = storage._db
            result: dict[str, float | dict[str, float]] = {}
            
            try:
                # Get total WAL size across all column families
                total_wal_size = db.get_property(b'rocksdb.total-wal-size')
                if total_wal_size:
                    result['total_wal_size'] = float(total_wal_size.decode('utf-8'))
                
                # Get WAL size per column family
                wal_per_cf: dict[str, float] = {}
                for cf in db.column_families:
                    cf_wal_size = db.get_property(b'rocksdb.size-all-mem-tables', cf)
                    if cf_wal_size:
                        cf_name = cf.name.decode('utf-8')
                        wal_per_cf[cf_name] = float(cf_wal_size.decode('utf-8'))
                
                if wal_per_cf:
                    result['wal_size_per_cf'] = wal_per_cf
                
                return result
            except Exception as e:
                self.log.error('error getting rocksdb wal stats', error=str(e))
                return {'error': str(e)}
        else:
            return {'error': f'storage is not RocksDB: {type(storage).__name__}'}
