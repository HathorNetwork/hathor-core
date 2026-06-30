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

from __future__ import annotations

import os
import tempfile

import htr_lib
from structlog import get_logger
from typing_extensions import assert_never

from hathor.storage import rocksdb_compat

logger = get_logger()
_DB_NAME = 'data_v2.db'


class RocksDBStorage:
    """Owns the process's primary RocksDB handle, backed by the Rust storage layer
    (`htr_lib.RocksDb`; design: plans/rust-rocksdb-storage.md).

    Python consumers use the python-rocksdb-shaped facade returned by `get_db()`
    (see `hathor.storage.rocksdb_compat`); Rust-native readers share the same handle
    through `get_db().inner`. Open options live in Rust (`build_options` in
    htr-rs/crates/htr-lib/src/storage/mod.rs), mirroring the ones python-rocksdb was
    configured with.
    """

    def __init__(
        self,
        path: str | tempfile.TemporaryDirectory,
        cache_capacity: int | None = None,
    ) -> None:
        self.log = logger.new()
        # We have to keep a reference to the TemporaryDirectory because it is cleaned up when garbage collected.
        self.path, self.temp_dir = self._get_path_and_temp_dir(path)

        db_path = os.path.join(self.path, _DB_NAME)
        inner = htr_lib.RocksDb(db_path, cache_capacity)
        self._db = rocksdb_compat.DB(inner)
        self.log.info('starting rocksdb', path=self.path)
        self.log.debug('open db', cf_list=[cf.name.decode('ascii') for cf in self._db.column_families])

    @staticmethod
    def create_temp(cache_capacity: int | None = None) -> RocksDBStorage:
        """Create a RocksDBStorage instance with a temporary directory."""
        return RocksDBStorage(path=tempfile.TemporaryDirectory(), cache_capacity=cache_capacity)

    @staticmethod
    def _get_path_and_temp_dir(
        path: str | tempfile.TemporaryDirectory,
    ) -> tuple[str, tempfile.TemporaryDirectory | None]:
        match path:
            case str():
                return path, None
            case tempfile.TemporaryDirectory():
                return path.name, path
            case _:
                assert_never(path)

    def get_db(self) -> rocksdb_compat.DB:
        return self._db

    def get_or_create_column_family(self, cf_name: bytes) -> rocksdb_compat.ColumnFamilyHandle:
        cf = self._db.get_column_family(cf_name)
        if cf is None:
            cf = self._db.create_column_family(cf_name, rocksdb_compat.ColumnFamilyOptions())
        return cf

    def close(self) -> None:
        self._db.close()
