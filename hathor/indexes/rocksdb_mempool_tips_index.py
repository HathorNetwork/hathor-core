# Copyright 2021 Hathor Labs
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

from typing import TYPE_CHECKING, Iterable, Optional

from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.indexes.memory_mempool_tips_index import MemoryMempoolTipsIndex
from hathor.indexes.mempool_tips_index import ByteCollectionMempoolTipsIndex
from hathor.indexes.rocksdb_utils import RocksDBSimpleSet
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

    from hathor.storage import RocksDBStorage
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()

_CF_NAME_MEMPOOL_TIPS_INDEX = b'mempool-tips-index'
_CF_NAME_MEMPOOL_TIPS_INDEX_META = b'mempool-tips-index-meta'
_DB_NAME: str = 'mempool_tips'
_DB_EMPTY_KEY = b'empty'
_DB_EMPTY_VALUE = b'1'


class SimpleRocksDBMempoolTipsIndex(MemoryMempoolTipsIndex):
    """Memory-backed mempool tips index with a persistent marker for the known-empty case."""

    def __init__(self, rocksdb_storage: 'RocksDBStorage', *, settings: HathorSettings) -> None:
        super().__init__(settings=settings)
        self._db = rocksdb_storage.get_db()
        self._cf_meta = rocksdb_storage.get_or_create_column_family(_CF_NAME_MEMPOOL_TIPS_INDEX_META)

    def still_needs_initialization(self, tx_storage: 'TransactionStorage') -> bool:
        return not self.is_empty_marker_set()

    def init_finish(self, tx_storage: 'TransactionStorage') -> None:
        self._sync_empty_marker()

    def update(self, tx: BaseTransaction, *, force_remove: bool = False) -> None:
        super().update(tx, force_remove=force_remove)
        self._sync_empty_marker()

    def is_empty_marker_set(self) -> bool:
        return self._db.get((self._cf_meta, _DB_EMPTY_KEY)) == _DB_EMPTY_VALUE

    def _sync_empty_marker(self) -> None:
        if self._index:
            self._clear_empty_marker()
        else:
            self._set_empty_marker()

    def _set_empty_marker(self) -> None:
        self._db.put((self._cf_meta, _DB_EMPTY_KEY), _DB_EMPTY_VALUE)

    def _clear_empty_marker(self) -> None:
        self._db.delete((self._cf_meta, _DB_EMPTY_KEY))


class RocksDBMempoolTipsIndex(ByteCollectionMempoolTipsIndex):
    _index: RocksDBSimpleSet

    def __init__(self, db: 'rocksdb.DB', *, settings: HathorSettings, cf_name: Optional[bytes] = None) -> None:
        super().__init__(settings=settings)
        self.log = logger.new()
        _cf_name = cf_name or _CF_NAME_MEMPOOL_TIPS_INDEX
        self._index = RocksDBSimpleSet(db, self.log, cf_name=_cf_name)

    def get_db_name(self) -> Optional[str]:
        # XXX: we don't need it to be parametrizable, so this is fine
        return _DB_NAME

    def force_clear(self) -> None:
        self._index.clear()

    def _discard(self, tx: bytes) -> None:
        self._index.discard(tx)

    def _discard_many(self, txs: Iterable[bytes]) -> None:
        self._index.discard_many(txs)

    def _add(self, tx: bytes) -> None:
        self._index.add(tx)

    def _add_many(self, txs: Iterable[bytes]) -> None:
        self._index.update(txs)
