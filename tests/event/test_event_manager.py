from hathor.event.model.event_type import EventType
from hathor.event.storage.memory_storage import EventMemoryStorage
from hathor.pubsub import HathorEvents
from hathor.util import not_none
from tests import unittest


class EventManagerTest(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.network = 'testnet'
        self.event_storage = EventMemoryStorage()
        self.manager = self.create_peer(
            self.network,
            enable_event_queue=True,
            event_storage=self.event_storage
        )

    def test_if_event_is_persisted(self) -> None:
        block = self.manager.tx_storage.get_best_block()
        self.manager.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=block)
        self.run_to_completion()
        self.assertIsNotNone(self.event_storage.get_event(0))

    def _fake_reorg_started(self) -> None:
        block = self.manager.tx_storage.get_best_block()
        # XXX: since we're faking these events, they don't neet to be consistent
        self.manager.pubsub.publish(HathorEvents.REORG_STARTED, old_best_height=1, old_best_block=block,
                                    new_best_height=1, new_best_block=block, reorg_size=1, common_block=block)

    def _fake_reorg_finished(self) -> None:
        self.manager.pubsub.publish(HathorEvents.REORG_FINISHED)

    def test_event_group(self) -> None:
        self._fake_reorg_started()
        self._fake_reorg_finished()
        self._fake_reorg_started()
        self._fake_reorg_finished()
        self.run_to_completion()

        event0 = not_none(self.event_storage.get_event(0))
        event1 = not_none(self.event_storage.get_event(1))
        event2 = not_none(self.event_storage.get_event(2))
        event3 = not_none(self.event_storage.get_event(3))
        event4 = not_none(self.event_storage.get_event(4))
        event5 = not_none(self.event_storage.get_event(5))
        event6 = not_none(self.event_storage.get_event(6))
        event7 = not_none(self.event_storage.get_event(7))
        event8 = not_none(self.event_storage.get_event(8))

        self.assertEqual(EventType(event0.type), EventType.LOAD_STARTED)
        self.assertEqual(EventType(event1.type), EventType.NEW_VERTEX_ACCEPTED)
        self.assertEqual(EventType(event2.type), EventType.NEW_VERTEX_ACCEPTED)
        self.assertEqual(EventType(event3.type), EventType.NEW_VERTEX_ACCEPTED)
        self.assertEqual(EventType(event4.type), EventType.LOAD_FINISHED)
        self.assertEqual(EventType(event5.type), EventType.REORG_STARTED)

        self.assertIsNotNone(event5.group_id)
        self.assertEqual(EventType(event6.type), EventType.REORG_FINISHED)
        self.assertIsNotNone(event6.group_id)
        self.assertEqual(event5.group_id, event6.group_id)

        self.assertNotEqual(event6.group_id, event7.group_id)
        self.assertIsNotNone(event7.group_id)
        self.assertEqual(event7.group_id, event8.group_id)

    def test_cannot_start_group_twice(self) -> None:
        self._fake_reorg_started()
        self.run_to_completion()
        with self.assertRaises(AssertionError):
            self._fake_reorg_started()
            self.run_to_completion()

    def test_cannot_finish_group_that_was_not_started(self) -> None:
        with self.assertRaises(AssertionError):
            self._fake_reorg_finished()
            self.run_to_completion()

    def test_cannot_finish_group_twice(self) -> None:
        self._fake_reorg_started()
        self._fake_reorg_finished()
        self.run_to_completion()
        with self.assertRaises(AssertionError):
            self._fake_reorg_finished()
            self.run_to_completion()
