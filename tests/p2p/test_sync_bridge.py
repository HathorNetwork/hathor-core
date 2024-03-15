from hathor.simulator import FakeConnection
from tests.simulation.base import SimulatorTestCase


class MixedSyncRandomSimulatorTestCase(SimulatorTestCase):
    __test__ = True

    async def test_the_three_transacting_miners(self) -> None:
        manager1 = self.create_peer(enable_sync_v1=True,  enable_sync_v2=False)
        manager2 = self.create_peer(enable_sync_v1=True,  enable_sync_v2=True)
        manager3 = self.create_peer(enable_sync_v1=False, enable_sync_v2=True)

        managers = [manager1, manager2, manager3]
        all_managers = managers
        miners = []
        tx_gens = []

        for manager in managers:
            miner = self.simulator.create_miner(manager, hashpower=100e6)
            await miner.start()
            miners.append(miner)
            tx_gen = self.simulator.create_tx_generator(manager, rate=2 / 60., hashpower=1e6, ignore_no_funds=True)
            await tx_gen.start()
            tx_gens.append(tx_gen)

        self.simulator.run(2000)

        self.simulator.add_connection(FakeConnection(manager1, manager2, latency=0.300))
        self.simulator.add_connection(FakeConnection(manager1, manager3, latency=0.300))
        self.simulator.add_connection(FakeConnection(manager2, manager3, latency=0.300))

        for tx_gen in tx_gens:
            tx_gen.stop()
        for miner in miners:
            miner.stop()

        self.simulator.run_until_complete(2000, 600)

        for idx, node in enumerate(all_managers):
            self.log.debug(f'checking node {idx}')
            self.assertConsensusValid(manager)

        for manager_a, manager_b in zip(all_managers[:-1], all_managers[1:]):
            # sync-v2 consensus test is more lenient (if sync-v1 assert passes sync-v2 assert will pass too)
            self.assertConsensusEqualSyncV2(manager_a, manager_b, strict_sync_v2_indexes=False)

    async def test_bridge_with_late_v2(self) -> None:
        manager1 = self.create_peer(enable_sync_v1=True,  enable_sync_v2=False)
        manager2 = self.create_peer(enable_sync_v1=True,  enable_sync_v2=True)
        manager3 = self.create_peer(enable_sync_v1=False, enable_sync_v2=True)

        managers = [manager1, manager2]
        all_managers = [manager1, manager2, manager3]
        miners = []
        tx_gens = []

        for manager in managers:
            miner = self.simulator.create_miner(manager, hashpower=100e6)
            await miner.start()
            miners.append(miner)
            tx_gen = self.simulator.create_tx_generator(manager, rate=2 / 60., hashpower=1e6, ignore_no_funds=True)
            await tx_gen.start()
            tx_gens.append(tx_gen)

        self.simulator.add_connection(FakeConnection(manager1, manager2, latency=0.300))
        self.simulator.run(2000)

        for tx_gen in tx_gens:
            tx_gen.stop()
        for miner in miners:
            miner.stop()

        self.simulator.add_connection(FakeConnection(manager2, manager3, latency=0.300))
        self.simulator.run_until_complete(2000, 600)

        for idx, node in enumerate(all_managers):
            self.log.debug(f'checking node {idx}')
            self.assertConsensusValid(manager)

        for manager_a, manager_b in zip(all_managers[:-1], all_managers[1:]):
            # sync-v2 consensus test is more lenient (if sync-v1 assert passes sync-v2 assert will pass too)
            self.assertConsensusEqualSyncV2(manager_a, manager_b, strict_sync_v2_indexes=False)
