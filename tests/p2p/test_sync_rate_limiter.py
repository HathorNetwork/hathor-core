from unittest.mock import MagicMock, Mock

from twisted.python.failure import Failure

from hathor.simulator import FakeConnection
from hathor.simulator.trigger import StopAfterNMinedBlocks
from tests import unittest
from tests.simulation.base import SimulatorTestCase


class SyncV1RandomSimulatorTestCase(unittest.SyncV1Params, SimulatorTestCase):
    __test__ = True

    seed_config = 1

    def test_sync_rate_limiter(self):
        manager1 = self.create_peer()

        miner1 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        trigger = StopAfterNMinedBlocks(miner1, quantity=20)
        self.simulator.run(3600, trigger=trigger)

        manager2 = self.create_peer()
        manager2.connections.MAX_ENABLED_SYNC = 0
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(3600)

        # Disable to reset all previous hits to the rate limiter.
        manager2.connections.disable_rate_limiter()
        manager2.connections.enable_rate_limiter(8, 2)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))
        protocol1 = connected_peers2[0]
        sync2 = protocol1.state.sync_agent
        sync2._send_tips = MagicMock()

        for i in range(100):
            sync2.send_tips()
            self.assertEqual(sync2._send_tips.call_count, min(i + 1, 8))
        self.assertEqual(sync2._send_tips.call_count, 8)

        sync2.send_tips()
        self.assertEqual(sync2._send_tips.call_count, 8)

        self.simulator._clock.advance(2000)
        self.assertTrue(sync2._send_tips.call_count, 16)

    def test_sync_rate_limiter_disconnect(self):
        # Test send_tips delayed calls cancelation with disconnection
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        manager2.connections.MAX_ENABLED_SYNC = 0

        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(3600)

        connections = manager2.connections
        connections.rate_limiter.reset(connections.GlobalRateLimiter.SEND_TIPS)
        connections.enable_rate_limiter(1, 1)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))

        protocol1 = connected_peers2[0]
        sync1 = protocol1.state.sync_agent
        sync1._send_tips = Mock(wraps=sync1._send_tips)

        sync1.send_tips()
        self.assertEqual(sync1._send_tips.call_count, 1)
        self.assertEqual(len(sync1._send_tips_call_later), 0)

        sync1.send_tips()
        self.assertEqual(sync1._send_tips.call_count, 1)
        self.assertEqual(len(sync1._send_tips_call_later), 1)

        sync1.send_tips()
        self.assertEqual(sync1._send_tips.call_count, 1)
        self.assertEqual(len(sync1._send_tips_call_later), 2)

        # Close the connection.
        conn12.disconnect(Failure(Exception('testing')))
        self.simulator.remove_connection(conn12)

        self.simulator.run(30)

        # Send tips should not be called any further since the connection has already been closed.
        self.assertEqual(sync1._send_tips.call_count, 1)
        # Residual delayed calls
        self.assertEqual(len(sync1._send_tips_call_later), 2)
        # The residual delayed calls should have been canceled
        for call_later in sync1._send_tips_call_later:
            self.assertFalse(call_later.active())

    def test_sync_rate_limiter_delayed_calls_draining(self):
        # Test the draining of delayed calls from _send_tips_call_later list
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        manager2.connections.MAX_ENABLED_SYNC = 0

        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(3600)

        connections = manager2.connections
        connections.rate_limiter.reset(connections.GlobalRateLimiter.SEND_TIPS)
        connections.enable_rate_limiter(1, 1)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))

        protocol1 = connected_peers2[0]
        sync1 = protocol1.state.sync_agent

        sync1.send_tips()
        self.assertEqual(len(sync1._send_tips_call_later), 0)

        sync1.send_tips()
        self.assertEqual(len(sync1._send_tips_call_later), 1)

        sync1.send_tips()
        self.assertEqual(len(sync1._send_tips_call_later), 2)

        sync1.send_tips()
        self.assertEqual(len(sync1._send_tips_call_later), 3)

        self.simulator.run(30)

        # Without disconnection, all the delayed calls
        # should have been executed
        self.assertEqual(len(sync1._send_tips_call_later), 0)

    def test_sync_rate_limiter_delayed_calls_stop(self):
        # Test the draining of delayed calls from _send_tips_call_later list
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        manager2.connections.MAX_ENABLED_SYNC = 0

        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(3600)

        connections = manager2.connections
        connections.rate_limiter.reset(connections.GlobalRateLimiter.SEND_TIPS)
        connections.enable_rate_limiter(1, 1)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))

        protocol1 = connected_peers2[0]
        sync1 = protocol1.state.sync_agent

        sync1.send_tips()
        self.assertEqual(len(sync1._send_tips_call_later), 0)

        # add delayed calls to the maximum
        max_delayed_calls = self._settings.MAX_GET_TIPS_DELAYED_CALLS
        for count in range(max_delayed_calls):
            sync1.send_tips()

        # we should have the maxinum delayed calls
        self.assertEqual(len(sync1._send_tips_call_later), max_delayed_calls)
        # Transport connection is still open
        self.assertFalse(conn12.tr2.disconnecting)

        # add one delayed call beyond the maximum
        sync1.send_tips()
        # we keep the maximum delayed calls allowed
        self.assertEqual(len(sync1._send_tips_call_later), max_delayed_calls)
        # Transport connection is aborted
        self.assertTrue(conn12.tr2.disconnecting)

        self.simulator.run(30)

        # A residual delayed calls is kept when connection closes
        self.assertEqual(len(sync1._send_tips_call_later), max_delayed_calls)
        # All residual tasks should have been canceled
        for call_later in sync1._send_tips_call_later:
            self.assertEqual(call_later.active(), False)
