from hathor.event.model.base_event import BaseEvent
from hathor.event.model.node_state import NodeState
from hathor.event.storage.rocksdb_storage import EventRocksDBStorage
from hathor_tests import unittest
from hathor_tests.utils import EventMocker


class EventStorageTest(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.event_mocker = EventMocker(self.rng)
        self.event_storage = EventRocksDBStorage(
            rocksdb_storage=self.create_rocksdb_storage(),
        )

    def test_save_event_and_retrieve(self) -> None:
        event = self.event_mocker.generate_mocked_event()
        self.event_storage.save_event(event)
        event_retrieved = self.event_storage.get_event(event.id)

        assert event_retrieved == event

    def test_save_events_and_retrieve(self) -> None:
        event1 = self.event_mocker.generate_mocked_event()
        event2 = self.event_mocker.generate_mocked_event()
        self.event_storage.save_events([event1, event2])
        event1_retrieved = self.event_storage.get_event(event1.id)
        event2_retrieved = self.event_storage.get_event(event2.id)

        assert event1_retrieved == event1
        assert event2_retrieved == event2

    def test_get_negative_key(self) -> None:
        with self.assertRaises(ValueError) as cm:
            self.event_storage.get_event(-1)

        self.assertEqual(
            'event.id \'-1\' must be non-negative',
            str(cm.exception)
        )

    def test_get_nonexistent_event(self) -> None:
        assert self.event_storage.get_event(0) is None
        assert self.event_storage.get_event(9999) is None

    def test_save_events_and_retrieve_the_last(self) -> None:
        last_event: BaseEvent | None = None
        for i in range(10):
            last_event = self.event_mocker.generate_mocked_event(i)
            self.event_storage.save_event(last_event)

        event_retrieved = self.event_storage.get_last_event()
        assert event_retrieved is not None
        assert last_event is not None
        assert event_retrieved.id == last_event.id

    def test_save_non_sequential(self) -> None:
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

    def test_iter_from_event_empty(self) -> None:
        self._test_iter_from_event(0)

    def test_iter_from_event_single(self) -> None:
        self._test_iter_from_event(1)

    def test_iter_from_event_multiple(self) -> None:
        self._test_iter_from_event(20)

    def _test_iter_from_event(self, n_events: int) -> None:
        expected_events = []
        for i in range(n_events):
            event = self.event_mocker.generate_mocked_event(i)
            expected_events.append(event)
            self.event_storage.save_event(event)

        actual_events = list(self.event_storage.iter_from_event(0))

        self.assertEqual(expected_events, actual_events)

    def test_iter_from_event_negative_key(self) -> None:
        with self.assertRaises(ValueError) as cm:
            events = self.event_storage.iter_from_event(-10)
            list(events)

        self.assertEqual(
            'event.id \'-10\' must be non-negative',
            str(cm.exception)
        )

    def test_save_events_and_retrieve_last_group_id(self) -> None:
        expected_group_id = 4

        self._populate_events_and_last_group_id(n_events=10, last_group_id=expected_group_id)

        actual_group_id = self.event_storage.get_last_group_id()

        assert expected_group_id == actual_group_id

    def _populate_events_and_last_group_id(self, n_events: int, last_group_id: int) -> None:
        for i in range(n_events):
            group_id = i if i <= last_group_id else None
            event = self.event_mocker.generate_mocked_event(i, group_id)
            self.event_storage.save_event(event)

    def test_get_empty_node_state(self) -> None:
        node_state = self.event_storage.get_node_state()

        assert node_state is None

    def test_save_node_state_and_retrieve(self) -> None:
        self.event_storage.save_node_state(NodeState.SYNC)
        node_state = self.event_storage.get_node_state()

        assert node_state == NodeState.SYNC

    def test_get_empty_event_queue_state(self) -> None:
        enabled = self.event_storage.get_event_queue_state()

        assert enabled is False

    def test_save_event_queue_enabled_and_retrieve(self) -> None:
        self.event_storage.save_event_queue_state(True)
        enabled = self.event_storage.get_event_queue_state()

        assert enabled is True

    def test_save_event_queue_disabled_and_retrieve(self) -> None:
        self.event_storage.save_event_queue_state(False)
        enabled = self.event_storage.get_event_queue_state()

        assert enabled is False

    def test_reset_events_empty_database(self) -> None:
        self._test_reset_events()

    def test_reset_all_empty_database(self) -> None:
        self._test_reset_events()

    def _test_reset_events(self) -> None:
        self.event_storage.reset_events()

        events = list(self.event_storage.iter_from_event(0))
        last_event = self.event_storage.get_last_event()
        last_group_id = self.event_storage.get_last_group_id()

        assert events == []
        assert last_event is None
        assert last_group_id is None

    def _test_reset_all(self) -> None:
        self.event_storage.reset_all()

        events = list(self.event_storage.iter_from_event(0))
        last_event = self.event_storage.get_last_event()
        last_group_id = self.event_storage.get_last_group_id()
        node_state = self.event_storage.get_node_state()
        event_queue_state = self.event_storage.get_event_queue_state()

        assert events == []
        assert last_event is None
        assert last_group_id is None
        assert node_state is None
        assert event_queue_state is False

    def test_reset_events_full_database(self) -> None:
        n_events = 10
        expected_last_group_id = 4
        expected_node_state = NodeState.SYNC

        self._populate_events_and_last_group_id(n_events=n_events, last_group_id=4)
        self.event_storage.save_node_state(expected_node_state)
        self.event_storage.save_event_queue_state(True)

        events = list(self.event_storage.iter_from_event(0))
        last_group_id = self.event_storage.get_last_group_id()
        node_state = self.event_storage.get_node_state()
        event_queue_state = self.event_storage.get_event_queue_state()

        assert len(events) == n_events
        assert last_group_id == expected_last_group_id
        assert node_state == expected_node_state
        assert event_queue_state is True

        self._test_reset_events()

        node_state = self.event_storage.get_node_state()
        event_queue_state = self.event_storage.get_event_queue_state()

        assert node_state == expected_node_state
        assert event_queue_state is True

    def test_reset_all_full_database(self) -> None:
        n_events = 10
        expected_last_group_id = 4
        expected_node_state = NodeState.SYNC

        self._populate_events_and_last_group_id(n_events=n_events, last_group_id=4)
        self.event_storage.save_node_state(expected_node_state)
        self.event_storage.save_event_queue_state(True)

        events = list(self.event_storage.iter_from_event(0))
        last_group_id = self.event_storage.get_last_group_id()
        node_state = self.event_storage.get_node_state()
        event_queue_state = self.event_storage.get_event_queue_state()

        assert len(events) == n_events
        assert last_group_id == expected_last_group_id
        assert node_state == expected_node_state
        assert event_queue_state is True

        self._test_reset_all()

        node_state = self.event_storage.get_node_state()
        event_queue_state = self.event_storage.get_event_queue_state()

        assert node_state is None
        assert event_queue_state is False
