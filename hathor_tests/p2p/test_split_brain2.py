import pytest

from hathor.graphviz import GraphvizVisualizer
from hathor.simulator import FakeConnection
from hathor_tests.simulation.base import SimulatorTestCase


class SyncMethodsTestCase(SimulatorTestCase):
    @pytest.mark.flaky(max_runs=3, min_passes=1)
    def test_split_brain(self) -> None:
        debug_pdf = False

        manager1 = self.create_peer()
        manager1.allow_mining_without_peers()

        manager2 = self.create_peer()
        manager2.allow_mining_without_peers()

        miner11 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner11.start()
        gen_tx11 = self.simulator.create_tx_generator(manager1, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx11.start()
        gen_tx12 = self.simulator.create_tx_generator(manager1, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx12.enable_double_spending()
        gen_tx12.start()

        miner21 = self.simulator.create_miner(manager2, hashpower=10e6)
        miner21.start()
        gen_tx21 = self.simulator.create_tx_generator(manager2, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx21.start()
        gen_tx22 = self.simulator.create_tx_generator(manager2, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx22.enable_double_spending()
        gen_tx22.start()

        self.simulator.run(400)

        if debug_pdf:
            dot1 = GraphvizVisualizer(manager1.tx_storage, include_verifications=True, include_funds=True).dot()
            dot1.render('dot1-pre')
            dot2 = GraphvizVisualizer(manager2.tx_storage, include_verifications=True, include_funds=True).dot()
            dot2.render('dot2-pre')

        self.assertTipsNotEqual(manager1, manager2)
        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)

        # input('Press enter to continue...')

        miner11.stop()
        gen_tx11.stop()
        gen_tx12.stop()
        miner21.stop()
        gen_tx21.stop()
        gen_tx22.stop()

        conn12 = FakeConnection(manager1, manager2)
        self.simulator.add_connection(conn12)

        self.simulator.run(300)

        if debug_pdf:
            dot1 = GraphvizVisualizer(manager1.tx_storage, include_verifications=True).dot()
            dot1.render('dot1-post')
            dot2 = GraphvizVisualizer(manager2.tx_storage, include_verifications=True).dot()
            dot2.render('dot2-post')

        self.assertSyncedProgress(conn12.proto1.state.sync_agent)
        self.assertSyncedProgress(conn12.proto2.state.sync_agent)
        self.assertTipsEqual(manager1, manager2)
        self.assertConsensusEqual(manager1, manager2)
        self.assertConsensusValid(manager1)
        self.assertConsensusValid(manager2)
