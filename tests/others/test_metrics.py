from hathor.metrics import Metrics
from hathor.pubsub import PubSubManager
from hathor.transaction.storage import TransactionCacheStorage, TransactionMemoryStorage
from hathor.util import reactor
from tests import unittest


class MetricsTest(unittest.TestCase):
    def test_cache_data_collection(self):
        """Test if cache-related data is correctly being collected from the
            TransactionCacheStorage
        """
        # Preparation
        base_storage = TransactionMemoryStorage(with_index=False)
        tx_storage = TransactionCacheStorage(base_storage, reactor)
        pubsub = PubSubManager(reactor)

        metrics = Metrics(
            pubsub=pubsub,
            avg_time_between_blocks=30,
            tx_storage=tx_storage,
            reactor=reactor
        )

        tx_storage.stats["hit"] = 10
        tx_storage.stats["miss"] = 20

        # Execution
        metrics._collect_data()

        # Assertion
        self.assertEquals(metrics.transaction_cache_hits, 10)
        self.assertEquals(metrics.transaction_cache_misses, 20)
