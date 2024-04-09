import tempfile
from typing import TYPE_CHECKING, NamedTuple

import pytest

from hathor.vertex_metadata import VertexMetadataService
from tests import unittest
from tests.utils import HAS_ROCKSDB

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb


class FakeTransaction(NamedTuple):
    hash: bytes
    timestamp: int


# XXX: sync-bridge used but it doesn't matter, it's only used to generate a random blockchain
class SimpleIndexesTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        # how many transactions will be generated on the same timestamp before increasing it by 1
        self.transactions = []
        repetitions = [1, 1, 10, 10, 10, 2, 1, 0, 0, 5, 5, 5, 0, 1, 1, 10, 10, 10, 1, 2, 3, 1, 100, 100, 1, 100, 0, 1]
        ts = self._settings.GENESIS_BLOCK_TIMESTAMP
        for rep in repetitions:
            for _ in range(rep):
                tx = FakeTransaction(self.rng.randbytes(32), ts)
                self.transactions.append(tx)
            ts += 1

    def create_tmp_rocksdb_db(self) -> 'rocksdb.DB':
        import rocksdb
        directory = tempfile.mkdtemp()
        self.tmpdirs.append(directory)
        options = rocksdb.Options(create_if_missing=True, error_if_exists=True)
        return rocksdb.DB(directory, options)

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_timestamp_index(self):
        # setup two indexes with different backends
        from hathor.indexes.memory_timestamp_index import MemoryTimestampIndex
        from hathor.indexes.rocksdb_timestamp_index import RocksDBTimestampIndex
        from hathor.indexes.timestamp_index import RangeIdx, ScopeType
        metadata_service = VertexMetadataService()
        rocksdb_index = RocksDBTimestampIndex(
            self.create_tmp_rocksdb_db(),
            scope_type=ScopeType.ALL,
            metadata_service=metadata_service
        )
        memory_index = MemoryTimestampIndex(scope_type=ScopeType.ALL, metadata_service=metadata_service)
        for tx in self.transactions:
            rocksdb_index.add_tx(tx)
            memory_index.add_tx(tx)

        # varying count so we stop at varied points
        offset_variety = set()
        for count in [2, 3, 5, 10, 100]:
            self.log.debug('with', count=count)
            idx_rocksdb = RangeIdx(0, 0)
            idx_memory = RangeIdx(0, 0)
            max_iters = 1000
            while max_iters > 0:
                self.log.debug('iter', idx=idx_memory)
                hashes_memory, idx_memory = memory_index.get_hashes_and_next_idx(idx_memory, count)
                hashes_rocksdb, idx_rocksdb = rocksdb_index.get_hashes_and_next_idx(idx_rocksdb, count)
                self.assertEqual(hashes_memory, hashes_rocksdb)
                self.assertEqual(idx_rocksdb, idx_memory)
                # XXX: we verified they're the same, doesn't matter which we pick:
                idx = idx_memory
                hashes = hashes_memory
                self.log.debug('indexes match', idx=idx, hashes=unittest.short_hashes(hashes))
                if idx is None:
                    break
                offset_variety.add(idx[1])
                max_iters -= 1
            else:
                self.fail('took too many iterations')

        # just making sure our tests covered enough different cases
        self.log.debug('offset variety', offsets=offset_variety)
        self.assertGreater(len(offset_variety), 2, msg='too little variety of offset, not enough coverage')
