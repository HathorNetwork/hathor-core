import tempfile

import pytest

from hathor.event.model.node_state import NodeState
from hathor.event.storage import EventStorage
from hathor.event.storage.memory_storage import EventMemoryStorage
from hathor.event.storage.rocksdb_storage import EventRocksDBStorage
from hathor.storage.rocksdb_storage import RocksDBStorage
from tests import unittest
from tests.utils import HAS_ROCKSDB, EventMocker


class EventStorageBaseTest(unittest.TestCase):
    __test__ = False

    event_storage: EventStorage

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

        self._populate_events_and_last_group_id(n_events=10, last_group_id=expected_group_id)

        actual_group_id = self.event_storage.get_last_group_id()

        assert expected_group_id == actual_group_id

    def _populate_events_and_last_group_id(self, n_events: int, last_group_id: int) -> None:
        for i in range(n_events):
            group_id = i if i <= last_group_id else None
            event = self.event_mocker.generate_mocked_event(i, group_id)
            self.event_storage.save_event(event)

    def test_get_empty_node_state(self):
        node_state = self.event_storage.get_node_state()

        assert node_state is None

    def test_save_node_state_and_retrieve(self):
        self.event_storage.save_node_state(NodeState.SYNC)
        node_state = self.event_storage.get_node_state()

        assert node_state == NodeState.SYNC

    def test_get_empty_event_queue_state(self):
        enabled = self.event_storage.get_event_queue_state()

        assert enabled is False

    def test_save_event_queue_enabled_and_retrieve(self):
        self.event_storage.save_event_queue_enabled()
        enabled = self.event_storage.get_event_queue_state()

        assert enabled is True

    def test_save_event_queue_disabled_and_retrieve(self):
        self.event_storage.save_event_queue_disabled()
        enabled = self.event_storage.get_event_queue_state()

        assert enabled is False

    def test_clear_events_empty_database(self):
        self._test_clear_events()

    def _test_clear_events(self) -> None:
        self.event_storage.clear_events()

        events = list(self.event_storage.iter_from_event(0))
        last_event = self.event_storage.get_last_event()
        last_group_id = self.event_storage.get_last_group_id()

        assert events == []
        assert last_event is None
        assert last_group_id is None

    def test_clear_events_full_database(self):
        n_events = 10
        expected_last_group_id = 4
        expected_node_state = NodeState.SYNC

        self._populate_events_and_last_group_id(n_events=n_events, last_group_id=4)
        self.event_storage.save_node_state(expected_node_state)
        self.event_storage.save_event_queue_enabled()

        events = list(self.event_storage.iter_from_event(0))
        last_group_id = self.event_storage.get_last_group_id()
        node_state = self.event_storage.get_node_state()
        event_queue_state = self.event_storage.get_event_queue_state()

        assert len(events) == n_events
        assert last_group_id == expected_last_group_id
        assert node_state == expected_node_state
        assert event_queue_state is True

        self._test_clear_events()

        node_state = self.event_storage.get_node_state()
        event_queue_state = self.event_storage.get_event_queue_state()

        assert node_state == expected_node_state
        assert event_queue_state is True


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
