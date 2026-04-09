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

from typing import TYPE_CHECKING, Optional

from structlog import get_logger

from hathor.indexes.nc_history_index import NCHistoryIndex
from hathor.indexes.rocksdb_tx_group_index import RocksDBTxGroupIndex
from hathor.indexes.rocksdb_utils import RocksDBIndexUtils

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

logger = get_logger()

_CF_NAME_NC_HISTORY_INDEX = b'nc-history-index'
_CF_NAME_NC_HISTORY_INDEX_STATS = b'nc-history-index-stats'
_DB_NAME: str = 'nc-history'


class RocksDBNCHistoryIndex(RocksDBTxGroupIndex[bytes], NCHistoryIndex, RocksDBIndexUtils):
    """RocksDB-persistent index of all transactions of a Nano Contract."""

    _KEY_SIZE = 32

    def __init__(self, db: 'rocksdb.DB', *, cf_name: Optional[bytes] = None) -> None:
        RocksDBTxGroupIndex.__init__(self, db, cf_name or _CF_NAME_NC_HISTORY_INDEX, _CF_NAME_NC_HISTORY_INDEX_STATS)

    def _serialize_key(self, key: bytes) -> bytes:
        return key

    def _deserialize_key(self, key_bytes: bytes) -> bytes:
        return key_bytes

    def get_db_name(self) -> Optional[str]:
        # XXX: we don't need it to be parametrizable, so this is fine
        return _DB_NAME

    def get_transaction_count(self, contract_id: bytes) -> int:
        assert self._stats is not None
        return self._stats.get_group_count(contract_id)
