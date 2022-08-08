import tempfile

import pytest

from hathor.event.storage.memory_storage import EventMemoryStorage
from hathor.event.storage.rocksdb_storage import EventRocksDBStorage
from hathor.storage.rocksdb_storage import RocksDBStorage
from tests import unittest
from tests.utils import HAS_ROCKSDB, EventMocker


class EventStorageBaseTest(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.event_mocker = EventMocker(self.rng)

    def test_save_event_and_retrieve(self):
        event = self.event_mocker.generate_mocked_event()
        self.event_storage.save_event(event)
        event_retrieved = self.event_storage.get_event(event.id)

        assert event_retrieved == event

    def test_get_key_nonpositive(self):
        with self.assertRaises(ValueError):
            self.event_storage.get_event(-1)

    def test_get_nonexistent_event(self):
        assert self.event_storage.get_event(0) is None
        assert self.event_storage.get_event(9999) is None

    def test_save_events_and_retrieve_the_last(self):
        last_event = None
        for i in range(10):
            last_event = self.event_mocker.generate_mocked_event(i)
            self.event_storage.save_event(last_event)

        event_retrieved = self.event_storage.get_last_event()
        assert event_retrieved.id == last_event.id

    def test_save_non_sequential(self):
        last_event = None
        for i in range(10):
            last_event = self.event_mocker.generate_mocked_event(i)
            self.event_storage.save_event(last_event)

        non_sequential_event = self.event_mocker.generate_mocked_event(11)
        with self.assertRaises(ValueError):
            self.event_storage.save_event(non_sequential_event)


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
