import unittest

from hathor.storage import RocksDBStorage
from hathor.sysctl import StorageSysctl


class StorageSysctlTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.storage = RocksDBStorage.create_temp()
        # Create a column family so we have more than just 'default'
        self.test_cf = self.storage.get_or_create_column_family(b'test-cf')
        self.sysctl = StorageSysctl(self.storage)

    def tearDown(self) -> None:
        self.storage.close()
        super().tearDown()

    def _write_data(self, num_entries: int = 100) -> None:
        """Write data to RocksDB so memtables and WAL have content."""
        db = self.storage.get_db()
        for i in range(num_entries):
            db.put(f'key-{i}'.encode(), f'value-{i}'.encode())
            db.put((self.test_cf, f'cf-key-{i}'.encode()), f'cf-value-{i}'.encode())

    def test_flush_runs_without_error(self) -> None:
        """Flush on an empty DB should succeed without raising."""
        self.sysctl.unsafe_set('rocksdb.flush', ())

    def test_flush_reduces_memtable_size(self) -> None:
        """After writing data and flushing, memtable size should decrease or stay small."""
        self._write_data(500)

        stats_before = self.sysctl.get('rocksdb.memtable_stats')
        self.sysctl.unsafe_set('rocksdb.flush', ())
        stats_after = self.sysctl.get('rocksdb.memtable_stats')

        # After a flush the memtable size should be <= what it was before
        self.assertLess(
            stats_after.get('total_size_bytes', 0),
            stats_before.get('total_size_bytes', 0),
        )

    # -- memtable_stats tests --

    def test_memtable_stats_returns_total_size_bytes(self) -> None:
        """memtable_stats should include total_size_bytes as a float."""
        self._write_data()

        stats = self.sysctl.get('rocksdb.memtable_stats')

        self.assertIn('total_size_bytes', stats)
        self.assertIsInstance(stats['total_size_bytes'], float)
        self.assertGreater(stats['total_size_bytes'], 0)

    def test_memtable_stats_returns_per_cf_sizes(self) -> None:
        """memtable_stats should include per-column-family memtable sizes."""
        self._write_data()

        stats = self.sysctl.get('rocksdb.memtable_stats')

        self.assertIn('size_bytes_per_cf', stats)
        per_cf = stats['size_bytes_per_cf']
        self.assertIsInstance(per_cf, dict)
        # Both CFs should be present since we wrote to both
        self.assertIn('default', per_cf)
        self.assertIsInstance(per_cf['default'], float)
        self.assertGreater(per_cf['default'], 0)
        self.assertIn('test-cf', per_cf)
        self.assertIsInstance(per_cf['test-cf'], float)
        self.assertGreater(per_cf['test-cf'], 0)

    def test_memtable_stats_includes_created_column_family(self) -> None:
        """The column family we created in setUp should appear in memtable_stats."""
        stats = self.sysctl.get('rocksdb.memtable_stats')

        self.assertIn('size_bytes_per_cf', stats)
        self.assertIn('test-cf', stats['size_bytes_per_cf'])

    def test_memtable_total_size_bytes_equals_sum_of_per_cf(self) -> None:
        """total_size_bytes should be the sum of all per-CF sizes."""
        self._write_data()

        stats = self.sysctl.get('rocksdb.memtable_stats')

        self.assertIn('total_size_bytes', stats)
        self.assertIn('size_bytes_per_cf', stats)
        self.assertAlmostEqual(stats['total_size_bytes'], sum(stats['size_bytes_per_cf'].values()))

    def test_memtable_stats_on_empty_db(self) -> None:
        """memtable_stats on a fresh DB should return without errors."""
        stats = self.sysctl.get('rocksdb.memtable_stats')

        self.assertNotIn('error', stats)
        self.assertIsInstance(stats, dict)

    # -- wal_stats tests --

    def test_wal_stats_returns_total_size_bytes(self) -> None:
        """wal_stats should include total_size_bytes of .log files on disk."""
        self._write_data()

        stats = self.sysctl.get('rocksdb.wal_stats')

        self.assertIn('total_size_bytes', stats)
        self.assertIsInstance(stats['total_size_bytes'], float)
        self.assertGreater(stats['total_size_bytes'], 0)

    def test_wal_stats_returns_file_count(self) -> None:
        """wal_stats should report the number of WAL files."""
        self._write_data()

        stats = self.sysctl.get('rocksdb.wal_stats')

        self.assertIn('file_count', stats)
        self.assertGreaterEqual(stats['file_count'], 1)

    def test_wal_stats_files_list(self) -> None:
        """wal_stats should list individual .log files with name and size."""
        self._write_data()

        stats = self.sysctl.get('rocksdb.wal_stats')

        self.assertIn('files', stats)
        self.assertIsInstance(stats['files'], list)
        for file_info in stats['files']:
            self.assertIn('name', file_info)
            self.assertIn('size_bytes', file_info)
            self.assertTrue(file_info['name'].endswith('.log'))
            self.assertGreater(file_info['size_bytes'], 0)

    def test_wal_stats_total_equals_sum_of_files(self) -> None:
        """total_size_bytes should equal the sum of individual file sizes."""
        self._write_data()

        stats = self.sysctl.get('rocksdb.wal_stats')

        files_sum = sum(f['size_bytes'] for f in stats['files'])
        self.assertAlmostEqual(stats['total_size_bytes'], files_sum)

    def test_wal_stats_on_empty_db(self) -> None:
        """wal_stats on a fresh DB should return valid structure without errors."""
        stats = self.sysctl.get('rocksdb.wal_stats')

        self.assertNotIn('error', stats)
        self.assertIsInstance(stats, dict)
        self.assertIn('total_size_bytes', stats)
        self.assertIn('file_count', stats)
        self.assertIn('files', stats)
