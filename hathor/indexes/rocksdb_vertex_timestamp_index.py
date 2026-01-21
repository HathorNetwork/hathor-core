#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import struct
from abc import ABC
from typing import Any, Iterator, final

import rocksdb
from structlog import get_logger
from typing_extensions import override

from hathor.indexes.rocksdb_utils import RocksDBIndexUtils, incr_key
from hathor.indexes.vertex_timestamp_index import VertexTimestampIndex
from hathor.transaction import BaseTransaction, Vertex

logger = get_logger()


class RocksDBVertexTimestampIndex(VertexTimestampIndex, RocksDBIndexUtils, ABC):
    cf_name: bytes
    db_name: str

    """
    This index uses the following key format:

        key = [tx.timestamp][tx.hash]
              |--4 bytes---||--32b--|

    It works nicely because rocksdb uses a tree sorted by key under the hood.
    """

    def __init__(self, db: rocksdb.DB) -> None:
        self.log = logger.new()
        RocksDBIndexUtils.__init__(self, db, self.cf_name)

    @final
    @override
    def get_db_name(self) -> str | None:
        return self.db_name

    @final
    @override
    def force_clear(self) -> None:
        self.clear()

    @staticmethod
    @final
    def _to_key(vertex: Vertex) -> bytes:
        """Make a key for a vertex."""
        key = bytearray()
        key.extend(struct.pack('>I', vertex.timestamp))
        assert len(vertex.hash) == 32
        key.extend(vertex.hash)
        assert len(key) == 4 + 32
        return bytes(key)

    @staticmethod
    @final
    def _from_key(key: bytes) -> tuple[int, bytes]:
        """Parse a key on the column-family."""
        assert len(key) == 4 + 32
        timestamp: int
        (timestamp,) = struct.unpack('>I', key[:4])
        tx_hash = key[4:]
        assert len(tx_hash) == 32
        return timestamp, tx_hash

    @final
    @override
    def _add_tx(self, tx: BaseTransaction) -> None:
        key = self._to_key(tx)
        self.log.debug('put key', key=key)
        self._db.put((self._cf, key), b'')

    @final
    @override
    def del_tx(self, tx: BaseTransaction) -> None:
        key = self._to_key(tx)
        self.log.debug('delete key', key=key)
        self._db.delete((self._cf, key))

    @final
    @override
    def _iter_sorted(
        self,
        *,
        tx_start: BaseTransaction | None,
        reverse: bool,
        inclusive: bool = False,
    ) -> Iterator[bytes]:
        it: Any = self._db.iterkeys(self._cf)
        if reverse:
            it = reversed(it)
            if tx_start is None:
                self.log.debug('seek to last')
                it.seek_to_last()
            else:
                # when reversed we increment the key by 1, which effectively goes to the end of a prefix
                self.log.debug('seek to', tx=tx_start)
                it.seek_for_prev(incr_key(self._to_key(tx_start)))
        else:
            if tx_start is None:
                self.log.debug('seek to first')
                it.seek_to_first()
            else:
                self.log.debug('seek to', tx=tx_start)
                it.seek(self._to_key(tx_start))

        it = (self._from_key(key) for _cf, key in it)
        try:
            _timestamp, first_tx_hash = next(it)
        except StopIteration:
            return
        if inclusive or not tx_start or tx_start.hash != first_tx_hash:
            yield first_tx_hash

        for _timestamp, tx_hash in it:
            self.log.debug('seek found', tx=tx_hash.hex())
            yield tx_hash
        self.log.debug('seek end')
