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
from typing import TYPE_CHECKING, Iterable, Optional, Sized, TypeVar

from structlog import get_logger

from hathor.indexes.rocksdb_utils import RocksDBIndexUtils, incr_key
from hathor.indexes.tx_group_index import TxGroupIndex
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

logger = get_logger()

KT = TypeVar('KT', bound=Sized)


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
    _CF_NAME: bytes

    def __init__(self, db: 'rocksdb.DB', cf_name: bytes) -> None:
        self.log = logger.new()
        RocksDBIndexUtils.__init__(self, db, cf_name)

    def force_clear(self) -> None:
        self.clear()

    @abstractmethod
    def _serialize_key(self, key: KT) -> bytes:
        """Serialize key, so it can be part of RockDB's key."""
        raise NotImplementedError

    @abstractmethod
    def _deserialize_key(self, _bytes: bytes) -> KT:
        """Deserialize RocksDB's key."""
        raise NotImplementedError

    @abstractmethod
    def _extract_keys(self, tx: BaseTransaction) -> Iterable[KT]:
        """Extract the keys related to a given tx. The transaction will be added to all extracted keys."""
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
            self.log.debug('put key', key=key)
            self._db.put((self._cf, self._to_rocksdb_key(key, tx)), b'')

    def remove_tx(self, tx: BaseTransaction) -> None:
        for key in self._extract_keys(tx):
            self.log.debug('delete key', key=key)
            self._db.delete((self._cf, self._to_rocksdb_key(key, tx)))

    def _get_from_key(self, key: KT) -> Iterable[bytes]:
        return self._util_get_from_key(key)

    def _get_sorted_from_key(self,
                             key: KT,
                             tx_start: Optional[BaseTransaction] = None,
                             reverse: bool = False) -> Iterable[bytes]:
        return self._util_get_from_key(key, tx_start, reverse)

    def _util_get_from_key(self,
                           key: KT,
                           tx: Optional[BaseTransaction] = None,
                           reverse: bool = False) -> Iterable[bytes]:
        self.log.debug('seek to', key=key)
        it = self._db.iterkeys(self._cf)
        if reverse:
            it = reversed(it)
            # when reversed we increment the key by 1, which effectively goes to the end of a prefix
            it.seek_for_prev(incr_key(self._to_rocksdb_key(key, tx)))
        else:
            it.seek(self._to_rocksdb_key(key, tx))
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
