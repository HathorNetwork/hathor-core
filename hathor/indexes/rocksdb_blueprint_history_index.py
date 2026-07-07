# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
