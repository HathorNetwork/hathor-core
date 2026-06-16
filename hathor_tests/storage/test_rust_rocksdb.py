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

"""Differential tests for the Rust RocksDB layer (`htr_lib.RocksDb`) against python-rocksdb.

The same seeded operation stream is applied to both backends on fresh databases and every
observable result is compared — point reads, batch effects, scan order in both directions,
seeks — plus the cross-open compatibility smoke for the librocksdb version gap
(`plans/rust-rocksdb-storage.md`, risk #1): a DB written by python-rocksdb must be readable
by the Rust layer.
"""

from pathlib import Path
from typing import Any

import htr_lib
import pytest
import rocksdb

from hathor.util import Random

CF_NAMES = ['default', 'tx', 'meta']


def make_python_db(path: str) -> rocksdb.DB:
    """Open python-rocksdb the same way hathor's RocksDBStorage does."""
    options = rocksdb.Options(
        table_factory=rocksdb.BlockBasedTableFactory(),
        compression=rocksdb.CompressionType.no_compression,
        allow_mmap_writes=True,
        allow_mmap_reads=True,
    )
    try:
        cf_names = rocksdb.list_column_families(path, options)
    except rocksdb.errors.RocksIOError:
        rocksdb.repair_db(path, options)
        cf_names = []
    column_families = {cf: rocksdb.ColumnFamilyOptions() for cf in cf_names}
    return rocksdb.DB(path, options, column_families=column_families)


def py_cf(db: rocksdb.DB, name: str) -> object:
    cf = db.get_column_family(name.encode('ascii'))
    if cf is None:
        cf = db.create_column_family(name.encode('ascii'), rocksdb.ColumnFamilyOptions())
    return cf


def make_op_stream(seed: int, count: int) -> list[tuple]:
    """A reproducible mixed stream of put/delete/batch ops over a small key space (small
    keyspace so deletes and overwrites actually collide)."""
    rng = Random(seed)
    ops: list[tuple] = []
    for _ in range(count):
        cf = rng.choice(CF_NAMES)
        key = bytes([rng.randrange(64)]) * rng.randrange(1, 4)
        roll = rng.random()
        if roll < 0.55:
            value = rng.randbytes(rng.randrange(0, 48))
            ops.append(('put', cf, key, value))
        elif roll < 0.75:
            ops.append(('delete', cf, key))
        else:
            batch_ops: list[tuple] = []
            for _ in range(rng.randrange(1, 6)):
                bcf = rng.choice(CF_NAMES)
                bkey = bytes([rng.randrange(64)])
                if rng.random() < 0.7:
                    batch_ops.append(('put', bcf, bkey, rng.randbytes(8)))
                else:
                    batch_ops.append(('delete', bcf, bkey))
            ops.append(('batch', batch_ops))
    return ops


def apply_to_python(db: rocksdb.DB, ops: list[tuple]) -> None:
    for op in ops:
        match op:
            case ('put', cf, key, value):
                db.put((py_cf(db, cf), key), value)
            case ('delete', cf, key):
                db.delete((py_cf(db, cf), key))
            case ('batch', batch_ops):
                batch = rocksdb.WriteBatch()
                for bop in batch_ops:
                    match bop:
                        case ('put', cf, key, value):
                            batch.put((py_cf(db, cf), key), value)
                        case ('delete', cf, key):
                            batch.delete((py_cf(db, cf), key))
                db.write(batch)


def apply_to_rust(db: htr_lib.RocksDb, ops: list[tuple]) -> None:
    existing = set(db.list_cfs())
    for name in CF_NAMES:
        if name not in existing:
            db.create_cf(name)
    for op in ops:
        match op:
            case ('put', cf, key, value):
                db.put(cf, key, value)
            case ('delete', cf, key):
                db.delete(cf, key)
            case ('batch', batch_ops):
                batch = htr_lib.RocksDbWriteBatch()
                for bop in batch_ops:
                    match bop:
                        case ('put', cf, key, value):
                            batch.put(cf, key, value)
                        case ('delete', cf, key):
                            batch.delete(cf, key)
                db.write(batch)


def python_scan(db: rocksdb.DB, cf: str, *, reverse: bool = False) -> list[tuple[bytes, bytes]]:
    it: Any = db.iteritems(py_cf(db, cf))
    if reverse:
        it = reversed(it)
        it.seek_to_last()
    else:
        it.seek_to_first()
    return [(key, value) for (_, key), value in it]


def rust_scan(db: htr_lib.RocksDb, cf: str, *, reverse: bool = False, chunk: int = 7) -> list[tuple[bytes, bytes]]:
    it = db.iterator(cf, mode='last' if reverse else 'first', reverse=reverse)
    items: list[tuple[bytes, bytes]] = []
    while chunk_items := it.next_chunk(chunk):
        items.extend(chunk_items)
    return items


@pytest.mark.parametrize('seed', [1, 2, 3])
def test_differential_op_stream(tmp_path: Path, seed: int) -> None:
    ops = make_op_stream(seed=seed, count=400)
    py_db = make_python_db(str(tmp_path / 'py.db'))
    rust_db = htr_lib.RocksDb(str(tmp_path / 'rust.db'))
    try:
        apply_to_python(py_db, ops)
        apply_to_rust(rust_db, ops)

        for cf in CF_NAMES:
            # Full scans must agree in content and order, both directions, across chunk sizes.
            py_items = python_scan(py_db, cf)
            assert rust_scan(rust_db, cf, chunk=1) == py_items
            assert rust_scan(rust_db, cf, chunk=7) == py_items
            assert rust_scan(rust_db, cf, chunk=10_000) == py_items
            assert rust_scan(rust_db, cf, reverse=True) == python_scan(py_db, cf, reverse=True)

            # Point reads agree over the whole keyspace (present and absent keys).
            for byte in range(64):
                for key in (bytes([byte]), bytes([byte]) * 2, bytes([byte]) * 3):
                    assert rust_db.get(cf, key) == py_db.get((py_cf(py_db, cf), key)), (cf, key)

            # multi_get agrees with the per-key gets.
            keys = [bytes([b]) for b in range(64)]
            expected = [py_db.get((py_cf(py_db, cf), key)) for key in keys]
            assert rust_db.multi_get(cf, keys) == expected
    finally:
        rust_db.close()


def test_differential_seeks(tmp_path: Path) -> None:
    py_db = make_python_db(str(tmp_path / 'py.db'))
    rust_db = htr_lib.RocksDb(str(tmp_path / 'rust.db'))
    try:
        keys = [bytes([b]) for b in range(0, 40, 3)]  # sparse keys: seeks land between keys
        for key in keys:
            py_db.put((py_cf(py_db, 'default'), key), key)
            rust_db.put('default', key, key)

        for target in range(42):
            target_key = bytes([target])

            it = py_db.iterkeys(py_cf(py_db, 'default'))
            it.seek(target_key)
            py_forward = [key for _, key in it]
            rust_it = rust_db.iterator('default', mode='seek', key=target_key)
            rust_forward = [key for key, _ in rust_it.next_chunk(10_000)]
            assert rust_forward == py_forward, target

            rit: Any = reversed(py_db.iterkeys(py_cf(py_db, 'default')))
            rit.seek_for_prev(target_key)
            py_backward = [key for _, key in rit]
            rust_rit = rust_db.iterator('default', mode='seek_for_prev', key=target_key, reverse=True)
            rust_backward = [key for key, _ in rust_rit.next_chunk(10_000)]
            assert rust_backward == py_backward, target
    finally:
        rust_db.close()


def test_rust_opens_python_created_db(tmp_path: Path) -> None:
    """A DB written by python-rocksdb is readable by the Rust layer (newer librocksdb reads
    older files). Informational only: the supported migration path is a fresh database +
    re-sync, and the reverse direction is known NOT to work — the newer librocksdb writes
    SST footers the old binding rejects ("Unknown Footer version"). Decision recorded in
    plans/rust-rocksdb-storage.md."""
    path = str(tmp_path / 'shared.db')
    py_db = make_python_db(path)
    py_db.put((py_cf(py_db, 'tx'), b'k1'), b'v1')
    py_db.put((py_cf(py_db, 'default'), b'k2'), b'v2')
    del py_db  # python-rocksdb has no close(); drop releases the LOCK

    rust_db = htr_lib.RocksDb(path)
    try:
        assert sorted(rust_db.list_cfs()) == ['default', 'tx']
        assert rust_db.get('tx', b'k1') == b'v1'
        assert rust_db.get('default', b'k2') == b'v2'
        rust_db.put('tx', b'k3', b'v3')
        assert rust_db.get('tx', b'k3') == b'v3'
    finally:
        rust_db.close()


def test_rust_get_property_and_key_may_exist(tmp_path: Path) -> None:
    rust_db = htr_lib.RocksDb(str(tmp_path / 'rust.db'))
    try:
        rust_db.put('default', b'k', b'v')
        assert rust_db.key_may_exist('default', b'k')
        value = rust_db.get_property('default', 'rocksdb.estimate-num-keys')
        assert value is not None
        assert int(value) >= 0
        assert rust_db.get_property('default', 'rocksdb.total-sst-files-size') is not None
    finally:
        rust_db.close()
