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
    from hathor.storage import RocksDBStorage


class StorageSysctl(Sysctl):
    def __init__(self, rocksdb_storage: 'RocksDBStorage') -> None:
        super().__init__()

        self.rocksdb_storage = rocksdb_storage
        self.register(
            'rocksdb.flush',
            None,
            self.set_rocksdb_flush,
        )
        self.register(
            'rocksdb.memtable_stats',
            self.get_rocksdb_memtable_stats,
            None,
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
        db = self.rocksdb_storage.get_db()
        # Flush all column families
        # The flush method is available in python-rocksdb
        try:
            db.flush()
            self.log.info('rocksdb flush completed successfully')
        except AttributeError:
            self.log.error('rocksdb flush method not available in this version of python-rocksdb')
        except Exception as e:
            self.log.error('error during rocksdb flush', error=str(e))

    def get_rocksdb_memtable_stats(self) -> dict[str, float | str | dict[str, float]]:
        """Get memtable statistics for RocksDB.

        Returns statistics including:
        - total_size_bytes: Total size of all memtables across all column families in bytes
        - size_bytes_per_cf: Dictionary with memtable size per column family in bytes

        Memtable sizes are correlated with WAL sizes: flushing memtables to SST files
        allows RocksDB to reclaim WAL disk space.
        """
        db = self.rocksdb_storage.get_db()
        result: dict[str, float | str | dict[str, float]] = {}

        try:
            # Get memtable size per column family
            size_bytes_per_cf: dict[str, float] = {}
            for cf in db.column_families:
                cf_size = db.get_property(b'rocksdb.size-all-mem-tables', cf)
                if cf_size:
                    cf_name = cf.name.decode('utf-8')
                    size_bytes_per_cf[cf_name] = float(cf_size.decode('utf-8'))

            if size_bytes_per_cf:
                result['size_bytes_per_cf'] = size_bytes_per_cf
                result['total_size_bytes'] = sum(size_bytes_per_cf.values())

            return result
        except Exception as e:
            self.log.error('error getting rocksdb memtable stats', error=str(e))
            return {'error': str(e)}

    def get_rocksdb_wal_stats(self) -> dict[str, float | str | list[dict[str, str | float]]]:
        """Get WAL (Write-Ahead Log) file statistics for RocksDB.

        Scans the RocksDB data directory for .log files (WAL files) and returns:
        - total_size_bytes: Total size of all WAL files in bytes
        - file_count: Number of WAL files
        - files: List of dicts with 'name' and 'size_bytes' for each WAL file

        This is useful to monitor WAL file accumulation on disk.
        """
        import os

        db_path = os.path.join(self.rocksdb_storage.path, 'data_v2.db')
        result: dict[str, float | str | list[dict[str, str | float]]] = {}

        try:
            files_info: list[dict[str, str | float]] = []
            total_size_bytes = 0.0

            if os.path.isdir(db_path):
                for entry in os.listdir(db_path):
                    if entry.endswith('.log'):
                        full_path = os.path.join(db_path, entry)
                        size_bytes = float(os.path.getsize(full_path))
                        files_info.append({'name': entry, 'size_bytes': size_bytes})
                        total_size_bytes += size_bytes

            result['total_size_bytes'] = total_size_bytes
            result['file_count'] = float(len(files_info))
            result['files'] = files_info

            return result
        except Exception as e:
            self.log.error('error getting rocksdb wal stats', error=str(e))
            return {'error': str(e)}
