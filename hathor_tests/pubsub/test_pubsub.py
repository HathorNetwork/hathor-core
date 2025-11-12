from hathor.pubsub import EventArguments, HathorEvents, PubSubManager
from hathor_tests.unittest import TestCase


class PubSubTestCase(TestCase):
    def test_duplicate_subscribe(self) -> None:
        def noop(event: HathorEvents, args: EventArguments) -> None:
            pass
        pubsub = PubSubManager(self.clock)
        pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, noop)
        pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, noop)
        self.assertEqual(1, len(pubsub._subscribers[HathorEvents.NETWORK_NEW_TX_ACCEPTED]))
