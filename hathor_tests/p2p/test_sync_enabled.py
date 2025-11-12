from hathor.simulator import FakeConnection
from hathor.simulator.trigger import StopAfterNMinedBlocks
from hathor_tests.simulation.base import SimulatorTestCase


class RandomSimulatorTestCase(SimulatorTestCase):
    def test_new_node_disabled(self) -> None:
        manager1 = self.create_peer()
        manager1.allow_mining_without_peers()

        miner1 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        trigger = StopAfterNMinedBlocks(miner1, quantity=20)
        self.simulator.run(3600, trigger=trigger)

        gen_tx1 = self.simulator.create_tx_generator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        self.simulator.run(3600)

        for _ in range(20):
            print()

        manager2 = self.create_peer()
        manager2.connections.MAX_ENABLED_SYNC = 0
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)

        self.assertFalse(conn12._proto2.is_sync_enabled())
        v2 = list(manager2.tx_storage.get_all_transactions())
        self.assertEqual(3, len(v2))

        self.simulator.run(3600)

        v1 = list(manager1.tx_storage.get_all_transactions())
        self.assertGreater(len(v1), 3)

        self.assertFalse(conn12._proto2.is_sync_enabled())
        v2 = list(manager2.tx_storage.get_all_transactions())
        self.assertEqual(3, len(v2))

    def test_sync_rotate(self) -> None:
        manager1 = self.create_peer()
        manager1.connections.MAX_ENABLED_SYNC = 3
        other_managers = [self.create_peer() for _ in range(15)]

        connections = []
        for other in other_managers:
            conn = FakeConnection(manager1, other, latency=0.05)
            connections.append(conn)
            self.simulator.add_connection(conn)

        self.simulator.run(600)

        ready = set(conn for conn in connections if conn.proto1.is_state(conn.proto1.PeerState.READY))
        self.assertEqual(len(ready), len(other_managers))

        enabled = set(conn for conn in connections if conn.proto1.is_sync_enabled())
        self.assertEqual(len(enabled), 3)

        manager1.connections._sync_rotate_if_needed(force=True)
        enabled2 = set(conn for conn in connections if conn.proto1.is_sync_enabled())
        self.assertEqual(len(enabled2), 3)
        if enabled == enabled2:
            manager1.connections._sync_rotate_if_needed(force=True)
            enabled2 = set(conn for conn in connections if conn.proto1.is_sync_enabled())
            self.assertEqual(len(enabled2), 3)
        # Chance of false positive: (1/comb(15, 3))**2 = 0.00000483
        self.assertNotEqual(enabled, enabled2)
