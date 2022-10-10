import tempfile

import pytest

from hathor.event.storage.memory_storage import EventMemoryStorage
from hathor.event.storage.rocksdb_storage import EventRocksDBStorage
from hathor.storage.rocksdb_storage import RocksDBStorage
from tests import unittest
from tests.utils import HAS_ROCKSDB, generate_mocked_event


class EventStorageBaseTest(unittest.TestCase):
    __test__ = False

    def test_save_event_and_retrieve(self):
        event = generate_mocked_event()
        self.event_storage.save_event(event)
        event_retrieved = self.event_storage.get_event(event.id)

        assert event_retrieved == event

    def test_get_key_nonpositive(self):
        with self.assertRaises(ValueError):
            self.event_storage.get_event(-1)

    def test_get_nonexistent_event(self):
        assert self.event_storage.get_event(0) is None
        assert self.event_storage.get_event(9999) is None


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class EventStorageRocksDBTest(EventStorageBaseTest):
    __test__ = True

    def setUp(self):
        super().setUp()
        self.directory = tempfile.mkdtemp()
        self.tmpdirs.append(self.directory)
        self.rocksdb_storage = RocksDBStorage(path=self.directory)
        self.event_storage = EventRocksDBStorage(self.rocksdb_storage)


class EventStorageMemoryTest(EventStorageBaseTest):
    __test__ = True

    def setUp(self):
        super().setUp()
        self.event_storage = EventMemoryStorage()
