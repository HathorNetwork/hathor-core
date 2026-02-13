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

"""
Performance comparison test for Memory vs RocksDB MempoolTipsIndex implementations.

This test compares the performance of:
- MemoryMempoolTipsIndex: Uses an in-memory Python set
- RocksDBMempoolTipsIndex: Uses RocksDB column family for persistence

The test measures the time taken for common operations:
- Adding transactions to the index
- Removing transactions from the index
- Iterating over all tips
- Getting the set of tips
- Update operations that simulate real-world usage patterns

Run with: pytest hathor_tests/tx/test_mempool_tips_index_performance.py -v -s
"""

import os
import time
from dataclasses import dataclass
from typing import Any, Callable

from hathor.conf.get_settings import get_global_settings
from hathor.indexes.memory_mempool_tips_index import MemoryMempoolTipsIndex
from hathor.indexes.rocksdb_mempool_tips_index import RocksDBMempoolTipsIndex
from hathor.storage import RocksDBStorage
from hathor_tests import unittest


@dataclass
class TimingResult:
    """Holds timing results for a single operation."""
    operation: str
    memory_time: float
    rocksdb_time: float
    count: int

    @property
    def ratio(self) -> float:
        """Return how many times slower RocksDB is compared to Memory."""
        if self.memory_time == 0:
            return float('inf')
        return self.rocksdb_time / self.memory_time

    def __str__(self) -> str:
        return (
            f"{self.operation:<30} | "
            f"{self.memory_time*1000:>10.3f}ms | "
            f"{self.rocksdb_time*1000:>10.3f}ms | "
            f"{self.ratio:>8.2f}x | "
            f"{self.count:>6}"
        )


class MempoolTipsIndexPerformanceTest(unittest.TestCase):
    """Performance comparison tests for MempoolTipsIndex implementations."""

    # Test sizes for varying mempool sizes
    TEST_SIZES = [10, 100, 500, 1000]

    def setUp(self) -> None:
        super().setUp()
        self.settings = get_global_settings()
        self._rocksdb_storage: RocksDBStorage | None = None

    def tearDown(self) -> None:
        if self._rocksdb_storage is not None:
            self._rocksdb_storage.close()
        super().tearDown()

    def _create_memory_index(self) -> MemoryMempoolTipsIndex:
        """Create a fresh MemoryMempoolTipsIndex."""
        return MemoryMempoolTipsIndex(settings=self.settings)

    def _create_rocksdb_index(self) -> RocksDBMempoolTipsIndex:
        """Create a fresh RocksDBMempoolTipsIndex with a temporary database."""
        if self._rocksdb_storage is not None:
            self._rocksdb_storage.close()
        self._rocksdb_storage = RocksDBStorage.create_temp()
        return RocksDBMempoolTipsIndex(
            self._rocksdb_storage.get_db(),
            settings=self.settings,
        )

    def _generate_tx_hashes(self, count: int) -> list[bytes]:
        """Generate a list of deterministic transaction hashes for testing."""
        return [os.urandom(32) for _ in range(count)]

    def _time_operation(self, operation: Callable[..., Any], iterations: int = 1) -> float:
        """Time an operation and return the elapsed time in seconds."""
        start = time.perf_counter()
        for _ in range(iterations):
            operation()
        end = time.perf_counter()
        return end - start

    def test_add_performance(self) -> None:
        """Compare performance of adding transactions to the index."""
        print("\n\n=== ADD PERFORMANCE COMPARISON ===")
        print(f"{'Operation':<30} | {'Memory':>12} | {'RocksDB':>12} | {'Ratio':>8} | {'Count':>6}")
        print("-" * 80)

        results: list[TimingResult] = []

        for size in self.TEST_SIZES:
            tx_hashes = self._generate_tx_hashes(size)

            # Memory index
            memory_index = self._create_memory_index()
            memory_time = self._time_operation(
                lambda hashes=tx_hashes, idx=memory_index: [idx._add(h) for h in hashes]
            )

            # RocksDB index
            rocksdb_index = self._create_rocksdb_index()
            rocksdb_time = self._time_operation(
                lambda hashes=tx_hashes, idx=rocksdb_index: [idx._add(h) for h in hashes]
            )

            result = TimingResult(
                operation=f"add {size} txs",
                memory_time=memory_time,
                rocksdb_time=rocksdb_time,
                count=size,
            )
            results.append(result)
            print(result)

        # All operations should complete (no assertions on timing)
        self.assertEqual(len(results), len(self.TEST_SIZES))

    def test_add_many_performance(self) -> None:
        """Compare performance of batch adding transactions."""
        print("\n\n=== BATCH ADD PERFORMANCE COMPARISON ===")
        print(f"{'Operation':<30} | {'Memory':>12} | {'RocksDB':>12} | {'Ratio':>8} | {'Count':>6}")
        print("-" * 80)

        results: list[TimingResult] = []

        for size in self.TEST_SIZES:
            tx_hashes = self._generate_tx_hashes(size)

            # Memory index
            memory_index = self._create_memory_index()
            memory_time = self._time_operation(
                lambda hashes=tx_hashes, idx=memory_index: idx._add_many(hashes)
            )

            # RocksDB index
            rocksdb_index = self._create_rocksdb_index()
            rocksdb_time = self._time_operation(
                lambda hashes=tx_hashes, idx=rocksdb_index: idx._add_many(hashes)
            )

            result = TimingResult(
                operation=f"add_many {size} txs",
                memory_time=memory_time,
                rocksdb_time=rocksdb_time,
                count=size,
            )
            results.append(result)
            print(result)

        self.assertEqual(len(results), len(self.TEST_SIZES))

    def test_discard_performance(self) -> None:
        """Compare performance of removing transactions from the index."""
        print("\n\n=== DISCARD PERFORMANCE COMPARISON ===")
        print(f"{'Operation':<30} | {'Memory':>12} | {'RocksDB':>12} | {'Ratio':>8} | {'Count':>6}")
        print("-" * 80)

        results: list[TimingResult] = []

        for size in self.TEST_SIZES:
            tx_hashes = self._generate_tx_hashes(size)

            # Memory index - add then discard
            memory_index = self._create_memory_index()
            memory_index._add_many(tx_hashes)
            memory_time = self._time_operation(
                lambda hashes=tx_hashes, idx=memory_index: [idx._discard(h) for h in hashes]
            )

            # RocksDB index - add then discard
            rocksdb_index = self._create_rocksdb_index()
            rocksdb_index._add_many(tx_hashes)
            rocksdb_time = self._time_operation(
                lambda hashes=tx_hashes, idx=rocksdb_index: [idx._discard(h) for h in hashes]
            )

            result = TimingResult(
                operation=f"discard {size} txs",
                memory_time=memory_time,
                rocksdb_time=rocksdb_time,
                count=size,
            )
            results.append(result)
            print(result)

        self.assertEqual(len(results), len(self.TEST_SIZES))

    def test_discard_many_performance(self) -> None:
        """Compare performance of batch removing transactions."""
        print("\n\n=== BATCH DISCARD PERFORMANCE COMPARISON ===")
        print(f"{'Operation':<30} | {'Memory':>12} | {'RocksDB':>12} | {'Ratio':>8} | {'Count':>6}")
        print("-" * 80)

        results: list[TimingResult] = []

        for size in self.TEST_SIZES:
            tx_hashes = self._generate_tx_hashes(size)

            # Memory index - add then discard
            memory_index = self._create_memory_index()
            memory_index._add_many(tx_hashes)
            memory_time = self._time_operation(
                lambda hashes=tx_hashes, idx=memory_index: idx._discard_many(hashes)
            )

            # RocksDB index - add then discard
            rocksdb_index = self._create_rocksdb_index()
            rocksdb_index._add_many(tx_hashes)
            rocksdb_time = self._time_operation(
                lambda hashes=tx_hashes, idx=rocksdb_index: idx._discard_many(hashes)
            )

            result = TimingResult(
                operation=f"discard_many {size} txs",
                memory_time=memory_time,
                rocksdb_time=rocksdb_time,
                count=size,
            )
            results.append(result)
            print(result)

        self.assertEqual(len(results), len(self.TEST_SIZES))

    def test_get_performance(self) -> None:
        """Compare performance of getting the set of tips."""
        print("\n\n=== GET PERFORMANCE COMPARISON ===")
        print(f"{'Operation':<30} | {'Memory':>12} | {'RocksDB':>12} | {'Ratio':>8} | {'Count':>6}")
        print("-" * 80)

        results: list[TimingResult] = []
        iterations = 100  # Run multiple times for more accurate timing

        for size in self.TEST_SIZES:
            tx_hashes = self._generate_tx_hashes(size)

            # Memory index
            memory_index = self._create_memory_index()
            memory_index._add_many(tx_hashes)
            memory_time = self._time_operation(
                lambda idx=memory_index: idx.get(),
                iterations=iterations,
            ) / iterations

            # RocksDB index
            rocksdb_index = self._create_rocksdb_index()
            rocksdb_index._add_many(tx_hashes)
            rocksdb_time = self._time_operation(
                lambda idx=rocksdb_index: idx.get(),
                iterations=iterations,
            ) / iterations

            result = TimingResult(
                operation=f"get {size} tips",
                memory_time=memory_time,
                rocksdb_time=rocksdb_time,
                count=size,
            )
            results.append(result)
            print(result)

        self.assertEqual(len(results), len(self.TEST_SIZES))

    def test_iteration_performance(self) -> None:
        """Compare performance of iterating over the index."""
        print("\n\n=== ITERATION PERFORMANCE COMPARISON ===")
        print(f"{'Operation':<30} | {'Memory':>12} | {'RocksDB':>12} | {'Ratio':>8} | {'Count':>6}")
        print("-" * 80)

        results: list[TimingResult] = []
        iterations = 100

        for size in self.TEST_SIZES:
            tx_hashes = self._generate_tx_hashes(size)

            # Memory index
            memory_index = self._create_memory_index()
            memory_index._add_many(tx_hashes)
            memory_time = self._time_operation(
                lambda idx=memory_index: list(iter(idx._index)),
                iterations=iterations,
            ) / iterations

            # RocksDB index
            rocksdb_index = self._create_rocksdb_index()
            rocksdb_index._add_many(tx_hashes)
            rocksdb_time = self._time_operation(
                lambda idx=rocksdb_index: list(iter(idx._index)),
                iterations=iterations,
            ) / iterations

            result = TimingResult(
                operation=f"iterate {size} tips",
                memory_time=memory_time,
                rocksdb_time=rocksdb_time,
                count=size,
            )
            results.append(result)
            print(result)

        self.assertEqual(len(results), len(self.TEST_SIZES))

    def test_mixed_operations_performance(self) -> None:
        """
        Compare performance of mixed operations that simulate real-world usage.

        This simulates what happens during block processing:
        1. Adding new transactions to the mempool
        2. Removing transactions when they are confirmed in blocks
        3. Getting tips to select transaction parents
        """
        print("\n\n=== MIXED OPERATIONS PERFORMANCE COMPARISON ===")
        print(f"{'Operation':<30} | {'Memory':>12} | {'RocksDB':>12} | {'Ratio':>8} | {'Count':>6}")
        print("-" * 80)

        results: list[TimingResult] = []

        for size in self.TEST_SIZES:
            # Generate initial transactions
            initial_hashes = self._generate_tx_hashes(size)
            # Generate new transactions to add during the test
            new_hashes = self._generate_tx_hashes(size // 2)
            # Select some transactions to remove (simulating block confirmation)
            remove_hashes = initial_hashes[:size // 4]

            def mixed_operations(index, initial, new, remove):
                # Add initial transactions
                index._add_many(initial)
                # Simulate getting tips for parent selection (common operation)
                _ = index.get()
                # Add some new transactions
                for h in new:
                    index._add(h)
                # Get tips again
                _ = index.get()
                # Remove some confirmed transactions
                index._discard_many(remove)
                # Final get tips
                _ = index.get()

            # Memory index
            memory_index = self._create_memory_index()
            memory_time = self._time_operation(
                lambda: mixed_operations(memory_index, initial_hashes, new_hashes, remove_hashes)
            )

            # RocksDB index
            rocksdb_index = self._create_rocksdb_index()
            rocksdb_time = self._time_operation(
                lambda: mixed_operations(rocksdb_index, initial_hashes, new_hashes, remove_hashes)
            )

            result = TimingResult(
                operation=f"mixed ops {size} base",
                memory_time=memory_time,
                rocksdb_time=rocksdb_time,
                count=size + size // 2,  # total operations
            )
            results.append(result)
            print(result)

        self.assertEqual(len(results), len(self.TEST_SIZES))

    def test_churn_performance(self) -> None:
        """
        Test performance under high churn (continuous add/remove).

        This simulates a busy node where transactions are constantly
        being added to and removed from the mempool.
        """
        print("\n\n=== CHURN PERFORMANCE COMPARISON ===")
        print(f"{'Operation':<30} | {'Memory':>12} | {'RocksDB':>12} | {'Ratio':>8} | {'Count':>6}")
        print("-" * 80)

        results: list[TimingResult] = []
        churn_iterations = 100

        for base_size in self.TEST_SIZES:
            # Start with a base set of transactions
            base_hashes = self._generate_tx_hashes(base_size)
            # Generate hashes for churn operations
            churn_hashes = self._generate_tx_hashes(churn_iterations)

            def churn_operations(index, base, churn):
                # Start with base transactions
                index._add_many(base)
                # Simulate high churn
                for i, h in enumerate(churn):
                    # Add new transaction
                    index._add(h)
                    # Every 10 transactions, remove the oldest from churn
                    if i >= 10:
                        index._discard(churn[i - 10])
                    # Occasionally get tips (every 5 txs)
                    if i % 5 == 0:
                        _ = index.get()

            # Memory index
            memory_index = self._create_memory_index()
            memory_time = self._time_operation(
                lambda: churn_operations(memory_index, base_hashes, churn_hashes)
            )

            # RocksDB index
            rocksdb_index = self._create_rocksdb_index()
            rocksdb_time = self._time_operation(
                lambda: churn_operations(rocksdb_index, base_hashes, churn_hashes)
            )

            result = TimingResult(
                operation=f"churn {base_size}+{churn_iterations}",
                memory_time=memory_time,
                rocksdb_time=rocksdb_time,
                count=base_size + churn_iterations,
            )
            results.append(result)
            print(result)

        self.assertEqual(len(results), len(self.TEST_SIZES))


class MempoolTipsIndexPerformanceSummary(unittest.TestCase):
    """Run all performance tests and print a summary table."""

    def test_performance_summary(self) -> None:
        """
        Run a comprehensive performance comparison and print a summary.

        This test provides an overview of the performance differences
        between Memory and RocksDB implementations across all operations.
        """
        settings = get_global_settings()
        rocksdb_storage: RocksDBStorage | None = None

        try:
            # Create indexes
            memory_index = MemoryMempoolTipsIndex(settings=settings)
            rocksdb_storage = RocksDBStorage.create_temp()
            rocksdb_index = RocksDBMempoolTipsIndex(
                rocksdb_storage.get_db(),
                settings=settings,
            )

            # Test parameters
            sizes = [10, 100, 500, 1000]
            all_results: list[TimingResult] = []

            print("\n" + "=" * 90)
            print("MEMPOOL TIPS INDEX PERFORMANCE COMPARISON: Memory vs RocksDB")
            print("=" * 90)
            print(f"\n{'Operation':<30} | {'Memory':>12} | {'RocksDB':>12} | {'Ratio':>8} | {'Count':>6}")
            print("-" * 90)

            for size in sizes:
                tx_hashes = [os.urandom(32) for _ in range(size)]

                # Test 1: Batch add
                memory_index.force_clear()
                rocksdb_index.force_clear()

                start = time.perf_counter()
                memory_index._add_many(tx_hashes)
                memory_add = time.perf_counter() - start

                start = time.perf_counter()
                rocksdb_index._add_many(tx_hashes)
                rocksdb_add = time.perf_counter() - start

                result = TimingResult(f"add_many({size})", memory_add, rocksdb_add, size)
                all_results.append(result)
                print(result)

                # Test 2: Get tips (with data already added)
                iterations = 50
                start = time.perf_counter()
                for _ in range(iterations):
                    _ = memory_index.get()
                memory_get = (time.perf_counter() - start) / iterations

                start = time.perf_counter()
                for _ in range(iterations):
                    _ = rocksdb_index.get()
                rocksdb_get = (time.perf_counter() - start) / iterations

                result = TimingResult(f"get({size} tips)", memory_get, rocksdb_get, size)
                all_results.append(result)
                print(result)

                # Test 3: Iterate
                start = time.perf_counter()
                for _ in range(iterations):
                    _ = list(iter(memory_index._index))
                memory_iter = (time.perf_counter() - start) / iterations

                start = time.perf_counter()
                for _ in range(iterations):
                    _ = list(iter(rocksdb_index._index))
                rocksdb_iter = (time.perf_counter() - start) / iterations

                result = TimingResult(f"iterate({size} tips)", memory_iter, rocksdb_iter, size)
                all_results.append(result)
                print(result)

                # Test 4: Discard many
                start = time.perf_counter()
                memory_index._discard_many(tx_hashes)
                memory_discard = time.perf_counter() - start

                start = time.perf_counter()
                rocksdb_index._discard_many(tx_hashes)
                rocksdb_discard = time.perf_counter() - start

                result = TimingResult(f"discard_many({size})", memory_discard, rocksdb_discard, size)
                all_results.append(result)
                print(result)

                print("-" * 90)

            # Print summary statistics
            print("\n" + "=" * 90)
            print("SUMMARY")
            print("=" * 90)

            avg_ratio = sum(r.ratio for r in all_results) / len(all_results)
            max_ratio = max(r.ratio for r in all_results)
            min_ratio = min(r.ratio for r in all_results)

            print(f"\nAverage RocksDB/Memory ratio: {avg_ratio:.2f}x slower")
            print(f"Maximum RocksDB/Memory ratio: {max_ratio:.2f}x slower")
            print(f"Minimum RocksDB/Memory ratio: {min_ratio:.2f}x slower")

            print("\nNOTE: The RocksDBIndexesManager currently uses MemoryMempoolTipsIndex")
            print("      because RocksDBMempoolTipsIndex is very slow (see manager.py line 433-434).")
            print("=" * 90)

        finally:
            if rocksdb_storage is not None:
                rocksdb_storage.close()

        # Test passes if we get here
        self.assertTrue(True)
