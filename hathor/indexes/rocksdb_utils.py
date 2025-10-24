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

from collections.abc import Collection
from typing import TYPE_CHECKING, Iterable, Iterator, NewType

from hathor.conf.get_settings import get_global_settings

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb
    import structlog


# the following type is used to help a little bit to distinguish when we're using a byte sequence that should only be
# internally used
InternalUid = NewType('InternalUid', bytes)
_INTERNAL_HATHOR_TOKEN_UID = InternalUid(b'\x00' * 32)


def to_internal_token_uid(token_uid: bytes) -> InternalUid:
    """Normalizes a token_uid so that the native token (\x00) will have the same length as custom tokens."""
    settings = get_global_settings()
    if token_uid == settings.HATHOR_TOKEN_UID:
        return _INTERNAL_HATHOR_TOKEN_UID
    assert len(token_uid) == 32
    return InternalUid(token_uid)


def from_internal_token_uid(token_uid: InternalUid) -> bytes:
    """De-normalizes the token_uid so that the native token is b'\x00' as expected"""
    assert len(token_uid) == 32
    settings = get_global_settings()
    if token_uid == _INTERNAL_HATHOR_TOKEN_UID:
        return settings.HATHOR_TOKEN_UID
    return token_uid


def incr_key(key: bytes) -> bytes:
    """ Numerically increment the key as if it were a big-endian number (up to 32 bytes).

    >>> incr_key(bytes.fromhex('0000')).hex()
    '0001'

    >>> incr_key(bytes.fromhex('0001')).hex()
    '0002'

    >>> incr_key(bytes.fromhex('00ff')).hex()
    '0100'

    >>> incr_key(bytes.fromhex('ffff')).hex()
    Traceback (most recent call last):
     ...
    ValueError: cannot increment anymore

    >>> incr_key(bytes.fromhex('0affff')).hex()
    '0b0000'
    """
    a = bytearray(key)
    for i in reversed(range(len(a))):
        if a[i] != 0xff:
            a[i] += 1
            break
        a[i] = 0x00
    else:
        raise ValueError('cannot increment anymore')
    return bytes(a)


class RocksDBIndexUtils:
    _db: 'rocksdb.DB'
    _cf: 'rocksdb.ColumnFamilyHandle'
    log: 'structlog.stdlib.BoundLogger'

    def __init__(self, db: 'rocksdb.DB', cf_name: bytes) -> None:
        self._log = self.log.new(cf=cf_name.decode('ascii'))
        self._db = db
        self._cf_name = cf_name
        self._ensure_cf_exists(cf_name)

    def _init_db(self):
        """ Inheritors of this class may implement this to initialize a column family when it is just created."""
        pass

    def _ensure_cf_exists(self, cf_name: bytes) -> None:
        """Ensure we have a working and column family, loading the previous one if it exists"""
        import rocksdb

        self._cf = self._db.get_column_family(cf_name)
        if self._cf is None:
            self._cf = self._db.create_column_family(cf_name, rocksdb.ColumnFamilyOptions())
            self._init_db()
        self._log.debug('got column family', is_valid=self._cf.is_valid, id=self._cf.id)

    def clear(self) -> None:
        old_id = self._cf.id
        self._log.debug('drop existing column family')
        self._db.drop_column_family(self._cf)
        del self._cf
        self._ensure_cf_exists(self._cf_name)
        new_id = self._cf.id
        assert self._cf is not None
        assert self._cf.is_valid
        assert new_id != old_id
        self._log.debug('got new column family', id=new_id, old_id=old_id)

    def _clone_into_dict(self) -> dict[bytes, bytes]:
        """This method will make a copy of the database into a plain dict, be careful when running on large dbs."""
        it = self._db.iteritems(self._cf)
        it.seek_to_first()
        return {k: v for (_, k), v in it}

    def get_all_internal(self) -> Iterable[bytes]:
        """
        Return all internal content of this index, sorted — that is, its rocksdb keys.
        Mostly useful for comparing different index instances in tests.
        """
        it = self._db.iterkeys(self._cf)
        it.seek_to_first()
        for _cf, rocksdb_key in it:
            yield rocksdb_key

    def get_value(self, key: bytes) -> bytes | None:
        """Get the value with the provided key, or None if it doesn't exist."""
        return self._db.get((self._cf, key))

    def put(self, key: bytes, value: bytes) -> None:
        """Put the value with the provided key."""
        self._db.put((self._cf, key), value)

    def delete(self, key: bytes) -> None:
        """Delete the value with the provided key."""
        self._db.delete((self._cf, key))

    def iterkeys(self) -> 'rocksdb.KeysIterator':
        """Iter over the keys in the column family."""
        return self._db.iterkeys(self._cf)


class RocksDBSimpleSet(Collection[bytes], RocksDBIndexUtils):
    def __init__(self, db: 'rocksdb.DB', log: 'structlog.stdlib.BoundLogger', *, cf_name: bytes) -> None:
        self.log = log
        super().__init__(db, cf_name)

    def __iter__(self) -> Iterator[bytes]:
        it = self._db.iterkeys(self._cf)
        it.seek_to_first()
        for _, elem in it:
            yield elem

    # XXX: should be `elem: bytes` but mypy complains
    def __contains__(self, elem: object) -> bool:
        assert isinstance(elem, bytes)
        # XXX: maybe this can be optimized with key_may_exist
        return self._db.get((self._cf, elem)) is not None

    def __len__(self) -> int:
        # XXX: under which conditions is this estimate not accurate?
        return int(self._db.get_property(b'rocksdb.estimate-num-keys', self._cf))

    def add(self, elem: bytes) -> None:
        self._db.put((self._cf, elem), b'')

    def update(self, it_elem: Iterable[bytes]) -> None:
        import rocksdb
        batch = rocksdb.WriteBatch()
        for elem in it_elem:
            batch.put((self._cf, elem), b'')
        self._db.write(batch)

    def discard(self, elem: bytes) -> None:
        self._db.delete((self._cf, elem))

    def discard_many(self, it_elem: Iterable[bytes]) -> None:
        import rocksdb
        batch = rocksdb.WriteBatch()
        for elem in it_elem:
            batch.delete((self._cf, elem))
        self._db.write(batch)
