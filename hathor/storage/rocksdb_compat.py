#  Copyright 2026 Hathor Labs
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

"""python-rocksdb-compatible facade over the Rust storage layer (`htr_lib.RocksDb`).

This module exposes the exact names and call shapes hathor-core used from python-rocksdb —
``DB`` with tuple-keyed ``get``/``put``/``delete``, ``WriteBatch``, ``ColumnFamilyHandle``,
seekable key/item/value iterators with ``reversed()`` support — so consumers swap
``import rocksdb`` for ``from hathor.storage import rocksdb_compat as rocksdb`` and change
nothing else. See ``plans/rust-rocksdb-storage.md`` for the inventory this surface was
derived from.

The underlying handle is shared with Rust-native readers (the batch-verification pipeline),
and every operation releases the GIL inside `htr_lib`.
"""

from __future__ import annotations

import itertools
from typing import Iterator, TypeAlias

import htr_lib
from typing_extensions import Self

# Chunk size for the iterator facades: one FFI call fetches this many (key, value) pairs.
# Large enough to amortize the crossing, small enough to keep memory bounded on huge scans.
_ITER_CHUNK_SIZE = 256

_cf_id_counter = itertools.count(1)

# python-rocksdb's point ops take either a plain key (default CF) or a (cf, key) tuple.
CfKey: TypeAlias = 'bytes | tuple[ColumnFamilyHandle, bytes]'


class ColumnFamilyHandle:
    """A named column-family reference. ``id`` is unique per (re-)creation, mirroring
    python-rocksdb where dropping and re-creating a CF yields a handle with a new id
    (RocksDBIndexUtils.clear asserts on exactly that)."""

    __slots__ = ('name', '_name_str', 'id', '_valid')

    def __init__(self, name: bytes) -> None:
        self.name = name
        self._name_str = name.decode('ascii')
        self.id = next(_cf_id_counter)
        self._valid = True

    @property
    def is_valid(self) -> bool:
        return self._valid

    def __repr__(self) -> str:
        return f'<ColumnFamilyHandle name={self._name_str!r} id={self.id} valid={self._valid}>'


class ColumnFamilyOptions:
    """Accepted and ignored: per-CF options were always defaults in hathor-core."""

    __slots__ = ()


class WriteBatch:
    """Records (cf, key[, value]) ops; ``DB.write`` materializes them into one atomic
    `htr_lib.RocksDbWriteBatch`. Reusable after ``clear()``, like python-rocksdb's."""

    __slots__ = ('_ops',)

    def __init__(self) -> None:
        self._ops: list[tuple[str, str, bytes, bytes | None]] = []

    def put(self, cf_key: tuple[ColumnFamilyHandle, bytes], value: bytes) -> None:
        cf, key = cf_key
        self._ops.append(('put', cf._name_str, key, value))

    def delete(self, cf_key: tuple[ColumnFamilyHandle, bytes]) -> None:
        cf, key = cf_key
        self._ops.append(('delete', cf._name_str, key, None))

    def count(self) -> int:
        return len(self._ops)

    def clear(self) -> None:
        self._ops.clear()


class _BaseIterator:
    """Seekable, direction-aware scan over one column family.

    Matches python-rocksdb usage: construct, optionally ``reversed()``, then call exactly one
    seek method, then iterate. Seeking resets the scan; the underlying chunked `htr_lib`
    iterator is opened lazily on the first ``__next__`` after a seek (or from the start/end
    of the CF when no seek was issued, per direction).
    """

    __slots__ = ('_db', '_cf', '_reverse', '_mode', '_key', '_inner', '_buffer', '_buffer_pos')

    def __init__(self, db: htr_lib.RocksDb, cf: ColumnFamilyHandle, *, reverse: bool = False) -> None:
        self._db = db
        self._cf = cf
        self._reverse = reverse
        self._mode: str | None = None
        self._key: bytes | None = None
        self._reset()

    def _reset(self) -> None:
        self._inner: htr_lib.RocksDbIterator | None = None
        self._buffer: list[tuple[bytes, bytes]] = []
        self._buffer_pos = 0

    def seek(self, key: bytes) -> None:
        self._mode, self._key = 'seek', key
        self._reset()

    def seek_for_prev(self, key: bytes) -> None:
        self._mode, self._key = 'seek_for_prev', key
        self._reset()

    def seek_to_first(self) -> None:
        self._mode, self._key = 'first', None
        self._reset()

    def seek_to_last(self) -> None:
        self._mode, self._key = 'last', None
        self._reset()

    def __reversed__(self) -> Self:
        """Return a reversed-direction iterator (callers seek it before iterating)."""
        return type(self)(self._db, self._cf, reverse=not self._reverse)

    def _peek_pair(self) -> tuple[bytes, bytes] | None:
        """The pair at the current position, without advancing; None when exhausted."""
        if self._inner is None:
            mode = self._mode if self._mode is not None else ('last' if self._reverse else 'first')
            self._inner = self._db.iterator(
                self._cf._name_str, mode=mode, key=self._key, reverse=self._reverse,
            )
            self._buffer = []
            self._buffer_pos = 0
        if self._buffer_pos >= len(self._buffer):
            self._buffer = self._inner.next_chunk(_ITER_CHUNK_SIZE)
            self._buffer_pos = 0
            if not self._buffer:
                return None
        return self._buffer[self._buffer_pos]

    def _next_pair(self) -> tuple[bytes, bytes]:
        pair = self._peek_pair()
        if pair is None:
            raise StopIteration
        self._buffer_pos += 1
        return pair


class KeysIterator(_BaseIterator):
    """Yields ``(cf_name, key)`` tuples, like python-rocksdb's keys iterator."""

    __slots__ = ()

    def __iter__(self) -> Iterator[tuple[bytes, bytes]]:
        return self

    def __next__(self) -> tuple[bytes, bytes]:
        key, _ = self._next_pair()
        return (self._cf.name, key)

    def get(self) -> tuple[bytes, bytes] | None:
        """The item at the current position, without advancing; None when exhausted."""
        pair = self._peek_pair()
        return None if pair is None else (self._cf.name, pair[0])


class ItemsIterator(_BaseIterator):
    """Yields ``((cf_name, key), value)`` tuples."""

    __slots__ = ()

    def __iter__(self) -> Iterator[tuple[tuple[bytes, bytes], bytes]]:
        return self

    def __next__(self) -> tuple[tuple[bytes, bytes], bytes]:
        key, value = self._next_pair()
        return ((self._cf.name, key), value)

    def get(self) -> tuple[tuple[bytes, bytes], bytes] | None:
        """The item at the current position, without advancing; None when exhausted."""
        pair = self._peek_pair()
        return None if pair is None else ((self._cf.name, pair[0]), pair[1])


class ValuesIterator(_BaseIterator):
    """Yields values only."""

    __slots__ = ()

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        _, value = self._next_pair()
        return value

    def get(self) -> bytes | None:
        """The value at the current position, without advancing; None when exhausted."""
        pair = self._peek_pair()
        return None if pair is None else pair[1]


class DB:
    """python-rocksdb-shaped facade over one `htr_lib.RocksDb` handle.

    Constructed by ``RocksDBStorage`` only — opening/creating the database lives there.
    Column-family handles are cached per name so repeated ``get_column_family`` calls return
    the same object; dropping invalidates the handle and a re-create yields a new id.
    """

    __slots__ = ('_inner', '_handles')

    def __init__(self, inner: htr_lib.RocksDb) -> None:
        self._inner = inner
        self._handles: dict[bytes, ColumnFamilyHandle] = {}
        for name in inner.list_cfs():
            name_bytes = name.encode('ascii')
            self._handles[name_bytes] = ColumnFamilyHandle(name_bytes)

    @property
    def inner(self) -> htr_lib.RocksDb:
        """The raw Rust handle (shared with Rust-native readers)."""
        return self._inner

    # -- column families ---------------------------------------------------

    @property
    def column_families(self) -> list[ColumnFamilyHandle]:
        return list(self._handles.values())

    def get_column_family(self, name: bytes) -> ColumnFamilyHandle | None:
        return self._handles.get(name)

    def create_column_family(self, name: bytes, options: ColumnFamilyOptions) -> ColumnFamilyHandle:
        self._inner.create_cf(name.decode('ascii'))
        handle = ColumnFamilyHandle(name)
        self._handles[name] = handle
        return handle

    def drop_column_family(self, cf: ColumnFamilyHandle) -> None:
        self._inner.drop_cf(cf._name_str)
        cf._valid = False
        self._handles.pop(cf.name, None)

    # -- point ops ----------------------------------------------------------

    @staticmethod
    def _split(cf_key: CfKey) -> tuple[str, bytes]:
        if isinstance(cf_key, tuple):
            cf, key = cf_key
            return cf._name_str, key
        return 'default', cf_key

    def get(self, cf_key: CfKey) -> bytes | None:
        cf_name, key = self._split(cf_key)
        return self._inner.get(cf_name, key)

    def put(self, cf_key: CfKey, value: bytes) -> None:
        cf_name, key = self._split(cf_key)
        self._inner.put(cf_name, key, value)

    def delete(self, cf_key: CfKey) -> None:
        cf_name, key = self._split(cf_key)
        self._inner.delete(cf_name, key)

    def key_may_exist(self, cf_key: CfKey) -> tuple[bool, None]:
        cf_name, key = self._split(cf_key)
        return (self._inner.key_may_exist(cf_name, key), None)

    def write(self, batch: WriteBatch) -> None:
        inner_batch = htr_lib.RocksDbWriteBatch()
        for op, cf_name, key, value in batch._ops:
            if op == 'put':
                assert value is not None
                inner_batch.put(cf_name, key, value)
            else:
                inner_batch.delete(cf_name, key)
        self._inner.write(inner_batch)

    # -- scans ----------------------------------------------------------------

    def iterkeys(self, cf: ColumnFamilyHandle | None = None) -> KeysIterator:
        return KeysIterator(self._inner, self._resolve(cf))

    def iteritems(self, cf: ColumnFamilyHandle | None = None) -> ItemsIterator:
        return ItemsIterator(self._inner, self._resolve(cf))

    def itervalues(self, cf: ColumnFamilyHandle | None = None) -> ValuesIterator:
        return ValuesIterator(self._inner, self._resolve(cf))

    def _resolve(self, cf: ColumnFamilyHandle | None) -> ColumnFamilyHandle:
        if cf is not None:
            return cf
        default = self._handles.get(b'default')
        assert default is not None, 'the default column family always exists'
        return default

    # -- misc -----------------------------------------------------------------

    def get_property(self, name: bytes, cf: ColumnFamilyHandle) -> bytes:
        value = self._inner.get_property(cf._name_str, name.decode('ascii'))
        assert value is not None, f'unknown rocksdb property: {name!r}'
        return value.encode('ascii')

    def flush(self) -> None:
        self._inner.flush()

    def close(self) -> None:
        self._inner.close()
