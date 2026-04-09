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

from abc import abstractmethod
from typing import Any, Callable, Generic, Iterator, Optional, Sized, TypeVar

import rocksdb
from structlog import get_logger
from typing_extensions import override

from hathor.indexes.rocksdb_utils import RocksDBIndexUtils, incr_key
from hathor.indexes.tx_group_index import TxGroupIndex
from hathor.transaction import BaseTransaction
from hathor.transaction.util import bytes_to_int, int_to_bytes

logger = get_logger()

KT = TypeVar('KT', bound=Sized)

GROUP_COUNT_VALUE_SIZE = 4  # in bytes


class _RocksDBTxGroupStatsIndex(RocksDBIndexUtils, Generic[KT]):
    def __init__(
        self,
        db: rocksdb.DB,
        cf_name: bytes,
        serialize_key: Callable[[KT], bytes],
    ) -> None:
        self.log = logger.new()
        super().__init__(db, cf_name)
        self._serialize_key = serialize_key

    def increase_group_count(self, key: KT) -> None:
        """Increase the group count for the provided key."""
        self._increment_group_count(key, amount=1)

    def decrease_group_count(self, key: KT) -> None:
        """Decrease the group count for the provided key."""
        self._increment_group_count(key, amount=-1)

    def _increment_group_count(self, key: KT, *, amount: int) -> None:
        """Increment the group count for the provided key with the provided amount."""
        count_key = self._serialize_key(key)
        count = self.get_group_count(key)
        new_count_bytes = int_to_bytes(number=count + amount, size=GROUP_COUNT_VALUE_SIZE)
        self._db.put((self._cf, count_key), new_count_bytes)

    def get_group_count(self, key: KT) -> int:
        """Return the group count for the provided key."""
        count_key = self._serialize_key(key)
        count_bytes = self._db.get((self._cf, count_key)) or b''
        return bytes_to_int(count_bytes)


class RocksDBTxGroupIndex(TxGroupIndex[KT], RocksDBIndexUtils):
    """RocksDB implementation of the TxGroupIndex. This class is abstract and cannot be used directly.

    Current implementation requires all keys to have the same size after serialization.

    This index uses rocksdb and the following key format:

        rocksdb_key = [key      ][tx.timestamp][tx.hash]
                      |_KEY_SIZE||--4 bytes---||--32b--|

    It works nicely because rocksdb uses a tree sorted by key under the hood.

    The timestamp must be serialized in big-endian, so ts1 > ts2 implies that bytes(ts1) > bytes(ts2),
    hence the transactions are sorted by timestamp.
    """

    _KEY_SIZE: int

    def __init__(self, db: rocksdb.DB, cf_name: bytes, stats_cf_name: bytes | None = None) -> None:
        self.log = logger.new()
        RocksDBIndexUtils.__init__(self, db, cf_name)
        self._stats = _RocksDBTxGroupStatsIndex(db, stats_cf_name, self._serialize_key) if stats_cf_name else None

    def force_clear(self) -> None:
        if self._stats:
            self._stats.clear()
        self.clear()

    @abstractmethod
    def _serialize_key(self, key: KT) -> bytes:
        """Serialize key, so it can be part of RockDB's key."""
        raise NotImplementedError

    @abstractmethod
    def _deserialize_key(self, _bytes: bytes) -> KT:
        """Deserialize RocksDB's key."""
        raise NotImplementedError

    def _to_rocksdb_key(self, key: KT, tx: Optional[BaseTransaction] = None) -> bytes:
        import struct
        rocksdb_key = self._serialize_key(key)
        assert len(rocksdb_key) == self._KEY_SIZE
        if tx:
            assert len(tx.hash) == 32
            rocksdb_key += struct.pack('>I', tx.timestamp) + tx.hash
            assert len(rocksdb_key) == self._KEY_SIZE + 4 + 32
        return rocksdb_key

    def _from_rocksdb_key(self, rocksdb_key: bytes) -> tuple[KT, int, bytes]:
        import struct
        assert len(rocksdb_key) == self._KEY_SIZE + 4 + 32
        key = self._deserialize_key(rocksdb_key[:self._KEY_SIZE])
        timestamp: int
        (timestamp,) = struct.unpack('>I', rocksdb_key[self._KEY_SIZE:self._KEY_SIZE + 4])
        tx_hash = rocksdb_key[self._KEY_SIZE + 4:]
        # Should we differentiate `_KEY_SIZE` and `_SERIALIZED_KEY_SIZE`?
        # assert len(key) == self._KEY_SIZE
        assert len(tx_hash) == 32
        return key, timestamp, tx_hash

    def add_tx(self, tx: BaseTransaction) -> None:
        for key in self._extract_keys(tx):
            self.add_single_key(key, tx)

    def add_single_key(self, key: KT, tx: BaseTransaction) -> None:
        self.log.debug('put key', key=key)
        internal_key = self._to_rocksdb_key(key, tx)
        if self._db.get((self._cf, internal_key)) is not None:
            return
        self._db.put((self._cf, internal_key), b'')
        if self._stats:
            self._stats.increase_group_count(key)

    def remove_tx(self, tx: BaseTransaction) -> None:
        for key in self._extract_keys(tx):
            self.remove_single_key(key, tx)

    def remove_single_key(self, key: KT, tx: BaseTransaction) -> None:
        self.log.debug('delete key', key=key)
        internal_key = self._to_rocksdb_key(key, tx)
        if self._db.get((self._cf, internal_key)) is None:
            return
        self._db.delete((self._cf, internal_key))
        if self._stats:
            self._stats.decrease_group_count(key)

    def _get_sorted_from_key(
        self,
        key: KT,
        tx_start: Optional[BaseTransaction] = None,
        reverse: bool = False
    ) -> Iterator[bytes]:
        self.log.debug('seek to', key=key)
        it: Any = self._db.iterkeys(self._cf)
        if reverse:
            it = reversed(it)
            # when reversed we increment the key by 1, which effectively goes to the end of a prefix
            it.seek_for_prev(incr_key(self._to_rocksdb_key(key, tx_start)))
        else:
            it.seek(self._to_rocksdb_key(key, tx_start))
        for _cf, rocksdb_key in it:
            key2, _, tx_hash = self._from_rocksdb_key(rocksdb_key)
            if key2 != key:
                break
            self.log.debug('seek found', tx=tx_hash.hex())
            yield tx_hash
        self.log.debug('seek end')

    def _is_key_empty(self, key: KT) -> bool:
        self.log.debug('seek to', key=key)
        it = self._db.iterkeys(self._cf)
        seek_key = self._to_rocksdb_key(key)
        it.seek(seek_key)
        cf_key = it.get()
        if not cf_key:
            return True
        _cf, rocksdb_key = cf_key
        # XXX: this means we reached the end it did not found any key
        if rocksdb_key == seek_key:
            return True
        key2, _, _ = self._from_rocksdb_key(rocksdb_key)
        is_empty = key2 != key
        self.log.debug('seek empty', is_empty=is_empty)
        return is_empty

    @override
    def get_latest_tx_timestamp(self, key: KT) -> int | None:
        it: Any = self._db.iterkeys(self._cf)
        it = reversed(it)
        # when reversed we increment the key by 1, which effectively goes to the end of a prefix
        it.seek_for_prev(incr_key(self._to_rocksdb_key(key)))
        try:
            _cf, rocksdb_key = next(it)
        except StopIteration:
            return None
        key2, tx_timestamp, _ = self._from_rocksdb_key(rocksdb_key)
        if key2 != key:
            return None
        assert key2 == key
        return tx_timestamp
