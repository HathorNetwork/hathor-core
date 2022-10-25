from hathor.event.storage.memory_storage import EventMemoryStorage
from hathor.pubsub import HathorEvents
from tests import unittest


class BaseEventManagerTest(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.event_storage = EventMemoryStorage()
        self.network = 'testnet'
        self.manager = self.create_peer(self.network, event_storage=self.event_storage)
        self.event_manager = self.manager.event_manager

    def test_if_event_is_persisted(self):
        self.manager.pubsub.publish(HathorEvents.NETWORK_BEST_BLOCK_FOUND,
                                    event={"test": "test1"})
        self.run_to_completion()
        self.assertIsNotNone(self.event_storage.get_event(0))

    def test_event_group(self):
        self.manager.pubsub.publish(HathorEvents.REORG_STARTED,
                                    event={"test": "test1"})
        self.manager.pubsub.publish(HathorEvents.REORG_FINISHED,
                                    event={"test": "test2"})
        self.manager.pubsub.publish(HathorEvents.REORG_STARTED,
                                    event={"test": "test3"})
        self.manager.pubsub.publish(HathorEvents.REORG_FINISHED,
                                    event={"test": "test4"})
        self.run_to_completion()
        event1 = self.event_storage.get_event(0)
        event2 = self.event_storage.get_event(1)
        event3 = self.event_storage.get_event(2)
        event4 = self.event_storage.get_event(3)
        self.assertEqual(HathorEvents(event1.type), HathorEvents.REORG_STARTED)
        self.assertIsNotNone(event1.group_id)
        self.assertEqual(HathorEvents(event2.type), HathorEvents.REORG_FINISHED)
        self.assertIsNotNone(event2.group_id)
        self.assertEqual(event1.group_id, event2.group_id)
        self.assertNotEqual(event2.group_id, event3.group_id)
        self.assertEqual(event3.group_id, event4.group_id)

    def test_cannot_start_group_twice(self):
        self.manager.pubsub.publish(HathorEvents.REORG_STARTED,
                                    event={"test": "test1"})
        self.run_to_completion()
        with self.assertRaises(AssertionError):
            self.manager.pubsub.publish(HathorEvents.REORG_STARTED,
                                        event={"test": "test1"})
            self.run_to_completion()

    def test_cannot_finish_group_that_was_not_started(self):
        with self.assertRaises(AssertionError):
            self.manager.pubsub.publish(HathorEvents.REORG_FINISHED,
                                        event={"test": "test1"})
            self.run_to_completion()

    def test_cannot_finish_group_twice(self):
        self.manager.pubsub.publish(HathorEvents.REORG_STARTED,
                                    event={"test": "test1"})
        self.manager.pubsub.publish(HathorEvents.REORG_FINISHED,
                                    event={"test": "test2"})
        self.run_to_completion()
        with self.assertRaises(AssertionError):
            self.manager.pubsub.publish(HathorEvents.REORG_FINISHED,
                                        event={"test": "test3"})
            self.run_to_completion()


class EventManagerWithSyncV1(unittest.SyncV1Params, BaseEventManagerTest):
    __test__ = True


class EventManagerWithSyncV2(unittest.SyncV1Params, BaseEventManagerTest):
    __test__ = True
