from unittest.mock import Mock

from hathor.event import EventManager
from hathor.event.storage.memory_storage import EventMemoryStorage
from hathor.event.websocket import EventWebsocketFactory
from hathor.pubsub import HathorEvents, PubSubManager
from tests import unittest


class BaseEventManagerTest(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.event_storage = EventMemoryStorage()
        self.event_ws_factory = Mock(spec_set=EventWebsocketFactory)
        self.network = 'testnet'
        pubsub = PubSubManager(self.clock)
        self.event_manager = EventManager(
            event_storage=self.event_storage,
            event_ws_factory=self.event_ws_factory,
            pubsub=pubsub,
            reactor=self.clock
        )
        self.manager = self.create_peer(
            self.network,
            event_manager=self.event_manager,
            pubsub=pubsub
        )

    def test_if_event_is_persisted(self):
        block = self.manager.tx_storage.get_best_block()
        self.manager.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=block)
        self.run_to_completion()
        self.assertIsNotNone(self.event_storage.get_event(0))

    def _fake_reorg_started(self):
        block = self.manager.tx_storage.get_best_block()
        # XXX: since we're faking these events, they don't neet to be consistent
        self.manager.pubsub.publish(HathorEvents.REORG_STARTED, old_best_height=1, old_best_block=block,
                                    new_best_height=1, new_best_block=block, reorg_size=1, common_block=block)

    def _fake_reorg_finished(self):
        self.manager.pubsub.publish(HathorEvents.REORG_FINISHED)

    def test_event_group(self):
        self._fake_reorg_started()
        self._fake_reorg_finished()
        self._fake_reorg_started()
        self._fake_reorg_finished()
        self.run_to_completion()
        # XXX: 0 is a tx update
        event1 = self.event_storage.get_event(1)
        event2 = self.event_storage.get_event(2)
        event3 = self.event_storage.get_event(3)
        event4 = self.event_storage.get_event(4)
        self.assertEqual(HathorEvents(event1.type), HathorEvents.REORG_STARTED)
        self.assertIsNotNone(event1.group_id)
        self.assertEqual(HathorEvents(event2.type), HathorEvents.REORG_FINISHED)
        self.assertIsNotNone(event2.group_id)
        self.assertEqual(event1.group_id, event2.group_id)
        self.assertNotEqual(event2.group_id, event3.group_id)
        self.assertEqual(event3.group_id, event4.group_id)

    def test_cannot_start_group_twice(self):
        self._fake_reorg_started()
        self.run_to_completion()
        with self.assertRaises(AssertionError):
            self._fake_reorg_started()
            self.run_to_completion()

    def test_cannot_finish_group_that_was_not_started(self):
        with self.assertRaises(AssertionError):
            self._fake_reorg_finished()
            self.run_to_completion()

    def test_cannot_finish_group_twice(self):
        self._fake_reorg_started()
        self._fake_reorg_finished()
        self.run_to_completion()
        with self.assertRaises(AssertionError):
            self._fake_reorg_finished()
            self.run_to_completion()


class SyncV1EventManager(unittest.SyncV1Params, BaseEventManagerTest):
    __test__ = True


class SyncV2EventManager(unittest.SyncV1Params, BaseEventManagerTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeEventManagerTest(unittest.SyncBridgeParams, SyncV2EventManager):
    pass
