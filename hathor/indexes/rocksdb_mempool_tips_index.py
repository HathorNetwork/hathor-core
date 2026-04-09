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
from hathor.indexes.mempool_tips_index import ByteCollectionMempoolTipsIndex
from hathor.indexes.rocksdb_utils import RocksDBSimpleSet

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

logger = get_logger()

_CF_NAME_MEMPOOL_TIPS_INDEX = b'mempool-tips-index'
_DB_NAME: str = 'mempool_tips'


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
