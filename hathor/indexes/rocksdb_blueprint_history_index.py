# Copyright 2025 Hathor Labs
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

import rocksdb
from typing_extensions import override

from hathor.indexes.blueprint_history_index import BlueprintHistoryIndex
from hathor.indexes.rocksdb_tx_group_index import RocksDBTxGroupIndex
from hathor.indexes.rocksdb_utils import RocksDBIndexUtils

_CF_NAME_BLUEPRINT_HISTORY_INDEX = b'blueprint-history-index'
_DB_NAME: str = 'blueprint-history'


class RocksDBBlueprintHistoryIndex(RocksDBTxGroupIndex[bytes], BlueprintHistoryIndex, RocksDBIndexUtils):
    _KEY_SIZE = 32

    def __init__(self, db: rocksdb.DB) -> None:
        RocksDBTxGroupIndex.__init__(self, db, _CF_NAME_BLUEPRINT_HISTORY_INDEX)

    @override
    def _serialize_key(self, key: bytes) -> bytes:
        return key

    @override
    def _deserialize_key(self, key_bytes: bytes) -> bytes:
        return key_bytes

    @override
    def get_db_name(self) -> str | None:
        return _DB_NAME
