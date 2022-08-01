# Copyright 2022 Hathor Labs
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

import os
from typing import List, Optional

import rocksdb
from structlog import get_logger

logger = get_logger()
_DB_NAME = 'data_v2.db'


class RocksDBStorage:
    """ Creates a RocksDB database
        Give clients the option to create column families
    """
    def __init__(self, path: str = './', cache_capacity: Optional[int] = None):
        self.log = logger.new()
        self._path = path

        db_path = os.path.join(path, _DB_NAME)
        lru_cache = cache_capacity and rocksdb.LRUCache(cache_capacity)
        table_factory = rocksdb.BlockBasedTableFactory(block_cache=lru_cache)
        options = rocksdb.Options(
            table_factory=table_factory,
            write_buffer_size=83886080,  # 80MB (default is 4MB)
            compression=rocksdb.CompressionType.no_compression,
            allow_mmap_writes=True,  # default is False
            allow_mmap_reads=True,  # default is already True
        )

        cf_names: List[bytes]
        try:
            # get the list of existing column families
            cf_names = rocksdb.list_column_families(db_path, options)
        except rocksdb.errors.RocksIOError:
            # this means the db doesn't exist, a repair will create one
            rocksdb.repair_db(db_path, options)
            cf_names = []

        # we need to open all column families
        column_families = {cf: rocksdb.ColumnFamilyOptions() for cf in cf_names}

        # finally, open the database
        self._db = rocksdb.DB(db_path, options, column_families=column_families)
        self.log.debug('open db', cf_list=[cf.name.decode('ascii') for cf in self._db.column_families])

    def get_db(self) -> 'rocksdb.DB':
        return self._db

    def get_or_create_column_family(self, cf_name) -> 'rocksdb.ColumnFamilyHandle':
        import rocksdb
        cf = self._db.get_column_family(cf_name)
        if cf is None:
            cf = self._db.create_column_family(cf_name, rocksdb.ColumnFamilyOptions())
        return cf
