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

from typing import TYPE_CHECKING, Optional

from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.indexes.memory_info_index import MemoryInfoIndex
from hathor.indexes.rocksdb_utils import RocksDBIndexUtils
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

    from hathor.indexes.manager import IndexesManager

logger = get_logger()

_CF_NAME_ADDRESS_INDEX = b'info-index'
_DB_NAME: str = 'info'

_DB_BLOCK_COUNT = b'block_count'
_DB_TX_COUNT = b'tx_count'
_DB_FIRST_TIMESTAMP = b'first_ts'
_DB_LATEST_TIMESTAMP = b'latest_ts'


class RocksDBInfoIndex(MemoryInfoIndex, RocksDBIndexUtils):
    def __init__(self, db: 'rocksdb.DB', *, settings: HathorSettings, cf_name: Optional[bytes] = None) -> None:
        self.log = logger.new()
        RocksDBIndexUtils.__init__(self, db, cf_name or _CF_NAME_ADDRESS_INDEX)
        MemoryInfoIndex.__init__(self, settings=settings)

    def init_start(self, indexes_manager: 'IndexesManager') -> None:
        self._load_all_values()
        self.log.info('loaded info-index', block_count=self._block_count, tx_count=self._tx_count,
                      first_timestamp=self._first_timestamp, latest_timestamp=self._latest_timestamp)

    def get_db_name(self) -> Optional[str]:
        return _DB_NAME

    def force_clear(self) -> None:
        super().force_clear()
        self._store_all_values()

    def _load_value(self, key: bytes) -> int:
        import struct
        db_value = self._db.get((self._cf, key))
        value, = struct.unpack('>I', db_value)
        return value

    def _load_all_values(self) -> None:
        self._block_count = self._load_value(_DB_BLOCK_COUNT)
        self._tx_count = self._load_value(_DB_TX_COUNT)
        self._first_timestamp = self._load_value(_DB_FIRST_TIMESTAMP)
        self._latest_timestamp = self._load_value(_DB_LATEST_TIMESTAMP)

    def _store_value(self, key: bytes, value: int) -> None:
        import struct
        db_value = struct.pack('>I', value)
        self._db.put((self._cf, key), db_value)

    def _store_all_values(self) -> None:
        self._store_value(_DB_BLOCK_COUNT, self._block_count)
        self._store_value(_DB_TX_COUNT, self._tx_count)
        self._store_value(_DB_FIRST_TIMESTAMP, self._first_timestamp)
        self._store_value(_DB_LATEST_TIMESTAMP, self._latest_timestamp)

    def update_timestamps(self, tx: BaseTransaction) -> None:
        super().update_timestamps(tx)
        self._store_all_values()

    def update_counts(self, tx: BaseTransaction, *, remove: bool = False) -> None:
        super().update_counts(tx, remove=remove)
        self._store_all_values()
