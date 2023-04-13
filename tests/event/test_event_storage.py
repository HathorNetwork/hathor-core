import tempfile

import pytest

from hathor.event.storage.memory_storage import EventMemoryStorage
from hathor.event.storage.rocksdb_storage import EventRocksDBStorage
from hathor.storage.rocksdb_storage import RocksDBStorage
from tests import unittest
from tests.utils import HAS_ROCKSDB, EventMocker


# TODO: Implement tests for new methods
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

    def test_get_negative_key(self):
        with self.assertRaises(ValueError) as cm:
            self.event_storage.get_event(-1)

        self.assertEqual(
            'event.id \'-1\' must be non-negative',
            str(cm.exception)
        )

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
        for i in range(10):
            event = self.event_mocker.generate_mocked_event(i)
            self.event_storage.save_event(event)

        non_sequential_event = self.event_mocker.generate_mocked_event(100)

        with self.assertRaises(ValueError) as cm:
            self.event_storage.save_event(non_sequential_event)

        self.assertEqual(
            'invalid event.id, ids must be sequential and leave no gaps',
            str(cm.exception)
        )

    def test_iter_from_event_empty(self):
        self._test_iter_from_event(0)

    def test_iter_from_event_single(self):
        self._test_iter_from_event(1)

    def test_iter_from_event_multiple(self):
        self._test_iter_from_event(20)

    def _test_iter_from_event(self, n_events):
        expected_events = []
        for i in range(n_events):
            event = self.event_mocker.generate_mocked_event(i)
            expected_events.append(event)
            self.event_storage.save_event(event)

        actual_events = list(self.event_storage.iter_from_event(0))

        self.assertEqual(expected_events, actual_events)

    def test_iter_from_event_negative_key(self):
        with self.assertRaises(ValueError) as cm:
            events = self.event_storage.iter_from_event(-10)
            list(events)

        self.assertEqual(
            'event.id \'-10\' must be non-negative',
            str(cm.exception)
        )

    def test_save_events_and_retrieve_last_group_id(self):
        expected_group_id = 4
        for i in range(10):
            group_id = i if i <= expected_group_id else None
            event = self.event_mocker.generate_mocked_event(i, group_id)
            self.event_storage.save_event(event)

        actual_group_id = self.event_storage.get_last_group_id()

        assert expected_group_id == actual_group_id


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
