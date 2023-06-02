from unittest.mock import MagicMock

from twisted.python.failure import Failure

from hathor.simulator import FakeConnection
from hathor.simulator.trigger import StopAfterNMinedBlocks
from tests import unittest
from tests.simulation.base import SimulatorTestCase


class BaseRandomSimulatorTestCase(SimulatorTestCase):
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

        manager2.connections.enable_rate_limiter(8, 2)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))
        protocol2 = connected_peers2[0]
        sync2 = protocol2.state.sync_manager
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
        protocol2 = connected_peers2[0]
        sync2 = protocol2.state.sync_manager
        sync2._send_tips = MagicMock()

        sync2.send_tips()
        self.assertEqual(sync2._send_tips.call_count, 1)

        sync2.send_tips()
        self.assertEqual(sync2._send_tips.call_count, 1)

        # Close the connection.
        conn12.disconnect(Failure(Exception('testing')))
        self.simulator.remove_connection(conn12)

        self.simulator.run(30)

        # Send tips should not be called any further since the connection has already been closed.
        self.assertEqual(sync2._send_tips.call_count, 1)

class SyncV1RandomSimulatorTestCase(unittest.SyncV1Params, BaseRandomSimulatorTestCase):
    __test__ = True


class SyncV2RandomSimulatorTestCase(unittest.SyncV2Params, BaseRandomSimulatorTestCase):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeRandomSimulatorTestCase(unittest.SyncBridgeParams, SyncV2RandomSimulatorTestCase):
    __test__ = True
