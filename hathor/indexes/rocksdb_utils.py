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
from typing import TYPE_CHECKING, Any, Dict, Iterable, Iterator

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb
    import structlog


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
    log: 'structlog.stdlib.BoundLogger'

    def __init__(self, db: 'rocksdb.DB') -> None:
        self._db = db

    def _fresh_cf(self, cf_name: bytes, options: Dict[str, Any]) -> 'rocksdb.ColumnFamilyHandle':
        """Ensure we have a working and fresh column family"""
        import rocksdb

        log_cf = self.log.new(cf=cf_name.decode('ascii'))
        _cf = self._db.get_column_family(cf_name)
        # XXX: dropping column because initialization currently expects a fresh index
        if _cf is not None:
            old_id = _cf.id
            log_cf.debug('drop existing column family')
            self._db.drop_column_family(_cf)
        else:
            old_id = None
            log_cf.debug('no need to drop column family')
        del _cf
        log_cf.debug('create fresh column family')
        # XXX: rocksdb.Options is a subclass of rocksdb.ColumnFamilyOptions, extra options will be ignored, this is
        #      useful for re-using an *options dict* (since an options instance cannot be reused)
        _cf = self._db.create_column_family(cf_name, rocksdb.Options(**options))
        new_id = _cf.id
        assert _cf is not None
        assert _cf.is_valid
        assert new_id != old_id
        log_cf.debug('got column family', is_valid=_cf.is_valid, id=_cf.id, old_id=old_id)
        return _cf


# XXX: should be `Collection[bytes]`, which only works on Python 3.9+
class RocksDBSimpleSet(Collection, RocksDBIndexUtils):
    def __init__(self, db: 'rocksdb.DB', options: Dict[str, Any], log: 'structlog.stdlib.BoundLogger',
                 *, cf_name: bytes) -> None:
        super().__init__(db)
        self.log = log
        self._cf_name = cf_name
        self._cf = self._fresh_cf(self._cf_name, options)

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
