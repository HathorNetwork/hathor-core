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

from typing import TYPE_CHECKING, Iterator, Optional

from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.indexes.rocksdb_utils import RocksDBIndexUtils, incr_key
from hathor.indexes.timestamp_index import ScopeType, TimestampIndex
from hathor.transaction import BaseTransaction
from hathor.util import collect_n

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

logger = get_logger()


class RocksDBTimestampIndex(TimestampIndex, RocksDBIndexUtils):
    """ Index of transactions sorted by their timestamps.

    This index uses the following key format:

        key = [tx.timestamp][tx.hash]
              |--4 bytes---||--32b--|

    It works nicely because rocksdb uses a tree sorted by key under the hood.
    """

    def __init__(self, db: 'rocksdb.DB', *, settings: HathorSettings, scope_type: ScopeType) -> None:
        TimestampIndex.__init__(self, scope_type=scope_type, settings=settings)
        self._name = scope_type.get_name()
        self.log = logger.new()
        RocksDBIndexUtils.__init__(self, db, f'timestamp-sorted-{self._name}'.encode())

    def get_db_name(self) -> Optional[str]:
        return f'timestamp_{self._name}'

    def force_clear(self) -> None:
        self.clear()

    def _to_key(self, timestamp: int, tx_hash: Optional[bytes] = None) -> bytes:
        """Make a key for a timestamp and optionally tx_hash, the key represents the membership itself."""
        import struct
        key = bytearray()
        key.extend(struct.pack('>I', timestamp))
        if tx_hash is None:
            assert len(key) == 4
            return bytes(key)
        assert len(tx_hash) == 32
        key.extend(tx_hash)
        assert len(key) == 4 + 32
        return bytes(key)

    def _from_key(self, key: bytes) -> tuple[int, bytes]:
        """Parse a key on the column-family."""
        import struct
        assert len(key) == 4 + 32
        timestamp: int
        (timestamp,) = struct.unpack('>I', key[:4])
        tx_hash = key[4:]
        assert len(tx_hash) == 32
        return timestamp, tx_hash

    def add_tx(self, tx: BaseTransaction) -> bool:
        key = self._to_key(tx.timestamp, tx.hash)
        is_new = self._db.get((self._cf, key)) is None
        if is_new:
            self._db.put((self._cf, key), b'')
        return is_new

    def del_tx(self, tx: BaseTransaction) -> None:
        key = self._to_key(tx.timestamp, tx.hash)
        self._db.delete((self._cf, key))

    def _iter(self, from_timestamp: Optional[int] = None, from_tx: Optional[bytes] = None,
              *, reverse: bool = False) -> Iterator[tuple[int, bytes]]:
        """ Iterate over transactions optionally starting from a timestamp/hash, by default from oldest to newest.

        If we request with from_timestamp=ts1 and from_tx=tx1, (ts1,tx1) will not be returned by the iterator.
        """
        if from_timestamp is None and from_tx is not None:
            raise ValueError('from_tx needs from_timestamp, but it is None')
        it = self._db.iterkeys(self._cf)
        if reverse:
            it = reversed(it)
            if from_timestamp is None:
                self.log.debug('seek to last')
                it.seek_to_last()
            else:
                # when reversed we increment the key by 1, which effectively goes to the end of a prefix
                self.log.debug('seek to', tx=from_tx)
                it.seek_for_prev(incr_key(self._to_key(from_timestamp, from_tx)))
        else:
            if from_timestamp is None:
                self.log.debug('seek to first')
                it.seek_to_first()
            else:
                self.log.debug('seek to', tx=from_tx)
                it.seek(self._to_key(from_timestamp, from_tx))
        first = True
        for _, key in it:
            timestamp, tx_hash = self._from_key(key)
            self.log.debug('seek found', tx=tx_hash.hex())
            # XXX: we can't blindly always skip the first element, because if it isn't on the index the seek would
            #      still work just fine, but go to the next closest key. While this doesn't happen from "internal" use,
            #      this # could happen from API calls that look up this index
            if first:
                first = False
                if from_timestamp is not None and from_timestamp == timestamp and from_tx == tx_hash:
                    continue
            yield timestamp, tx_hash
        self.log.debug('seek end')

    def get_newest(self, count: int) -> tuple[list[bytes], bool]:
        it = (x for _, x in self._iter(reverse=True))
        return collect_n(it, count)

    def get_older(self, timestamp: int, hash_bytes: bytes | None, count: int) -> tuple[list[bytes], bool]:
        it = (x for _, x in self._iter(timestamp, hash_bytes, reverse=True))
        return collect_n(it, count)

    def get_newer(self, timestamp: int, hash_bytes: bytes | None, count: int) -> tuple[list[bytes], bool]:
        it = (x for _, x in self._iter(timestamp, hash_bytes))
        return collect_n(it, count)

    def iter(self) -> Iterator[bytes]:
        it = self._db.iterkeys(self._cf)
        it.seek_to_first()
        for _, key in it:
            __, tx_hash = self._from_key(key)
            yield tx_hash

    def __contains__(self, elem: tuple[int, bytes]) -> bool:
        key = self._to_key(*elem)
        return self._db.get((self._cf, key)) is not None
