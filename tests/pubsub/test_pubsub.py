import threading
import time

from twisted.internet import threads
from twisted.python import threadable

from hathor.pubsub import HathorEvents, PubSubManager
from hathor.util import reactor
from tests import unittest


class PubSubTestCase(unittest.TestCase):
    def _waitForThread(self):
        """
        The reactor's threadpool is only available when the reactor is running,
        so to have a sane behavior during the tests we make a dummy
        L{threads.deferToThread} call.
        """
        # copied from twisted/test/test_threads.py [yan]
        return threads.deferToThread(time.sleep, 0)

    def test_pubsub_thread(self):
        """ Test pubsub function is always called in reactor thread.
        """
        def _on_new_event(*args):
            self.assertTrue(threadable.isInIOThread())

        pubsub = PubSubManager(reactor)
        pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, _on_new_event)

        def cb(_ignore):
            waiter = threading.Event()

            def threadedFunc():
                self.assertFalse(threadable.isInIOThread())
                pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED)
                waiter.set()

            reactor.callInThread(threadedFunc)
            waiter.wait(20)
            self.assertTrue(waiter.isSet())

        return self._waitForThread().addCallback(cb)

    def test_duplicate_subscribe(self):
        def noop():
            pass
        pubsub = PubSubManager(self.clock)
        pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, noop)
        pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, noop)
        self.assertEqual(1, len(pubsub._subscribers[HathorEvents.NETWORK_NEW_TX_ACCEPTED]))
