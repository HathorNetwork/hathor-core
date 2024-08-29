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

from typing import TYPE_CHECKING, Optional

from structlog import get_logger

from hathor.indexes.json_extended_cache import JsonExtendedCache
from hathor.indexes.rocksdb_utils import RocksDBIndexUtils
from hathor.types import VertexId

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

logger = get_logger()

_CF_NAME = b'json-extended-cache'
_DB_NAME: str = 'json-extended-cache'


class RocksDBJsonExtendedCache(JsonExtendedCache, RocksDBIndexUtils):
    def __init__(self, db: 'rocksdb.DB', *, cf_name: Optional[bytes] = None) -> None:
        self.log = logger.new()
        JsonExtendedCache.__init__(self)
        RocksDBIndexUtils.__init__(self, db, cf_name or _CF_NAME)

    def get_db_name(self) -> Optional[str]:
        return _DB_NAME

    def force_clear(self) -> None:
        self.clear()

    def get(self, vertex_id: VertexId) -> Optional[bytes]:
        return self._db.get((self._cf, vertex_id))

    def set(self, vertex_id: VertexId, data: bytes) -> None:
        self._db.put((self._cf, vertex_id), data)

    def invalidate(self, vertex_id: VertexId) -> None:
        self._db.delete((self._cf, vertex_id))
