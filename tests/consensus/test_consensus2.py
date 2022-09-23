from hathor.graphviz import GraphvizVisualizer
from tests import unittest
from tests.simulation.base import SimulatorTestCase
from tests.utils import add_custom_tx, gen_new_tx


class BaseConsensusSimulatorTestCase(SimulatorTestCase):
    def checkConflict(self, tx1, tx2):
        meta1 = tx1.get_metadata()
        meta2 = tx2.get_metadata()
        self.assertIn(tx1.hash, meta2.conflict_with)
        self.assertIn(tx2.hash, meta1.conflict_with)

        cnt = 0
        if not meta1.voided_by:
            cnt += 1
        if not meta2.voided_by:
            cnt += 1
        self.assertLessEqual(cnt, 1)

    def do_step(self, i, manager1, tx_base):
        txA = add_custom_tx(manager1, [(tx_base, 0)], n_outputs=2)
        self.graphviz.labels[txA.hash] = f'txA-{i}'

        txB = add_custom_tx(manager1, [(txA, 0)])
        self.graphviz.labels[txB.hash] = f'txB-{i}'
        txC = add_custom_tx(manager1, [(txA, 1)])
        self.graphviz.labels[txC.hash] = f'txC-{i}'

        txD1 = add_custom_tx(manager1, [(txC, 0)], base_parent=tx_base)
        self.graphviz.labels[txD1.hash] = f'txD1-{i}'
        txF2 = add_custom_tx(manager1, [(txB, 0), (txD1, 0)])
        self.graphviz.labels[txF2.hash] = f'txF2-{i}'

        txD2 = add_custom_tx(manager1, [(txC, 0)], base_parent=tx_base, inc_timestamp=1)
        self.graphviz.labels[txD2.hash] = f'txD2-{i}'
        txE = add_custom_tx(manager1, [(txD2, 0)], base_parent=tx_base)
        self.graphviz.labels[txE.hash] = f'txE-{i}'

        txF1 = add_custom_tx(manager1, [(txB, 0)], base_parent=tx_base)
        self.graphviz.labels[txF1.hash] = f'txF1-{i}'

        txG = add_custom_tx(manager1, [(txF2, 0)], base_parent=tx_base)
        self.graphviz.labels[txG.hash] = f'txG-{i}'

        txH = add_custom_tx(manager1, [(txF1, 0), (txG, 0)])
        self.graphviz.labels[txH.hash] = f'txH-{i}'

        self.checkConflict(txD1, txD2)
        self.checkConflict(txF1, txF2)

        return txH

    def test_two_conflicts_intertwined_once(self):
        manager1 = self.create_peer()
        manager1.allow_mining_without_peers()

        miner1 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        self.simulator.run(60)

        gen_tx1 = self.simulator.create_tx_generator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        self.simulator.run(300)
        gen_tx1.stop()

        # Our full node wallet has a callLater that checks for new utxos every 10 seconds.
        # If we don't run 10 seconds, the utxos generated on the create_tx_generator won't be available,
        # then we might get an insufficient fund error to create the next tx
        self.simulator.run(10)

        self.graphviz = GraphvizVisualizer(manager1.tx_storage, include_verifications=True, include_funds=True)

        address = manager1.wallet.get_unused_address(mark_as_used=False)
        value = 10
        initial = gen_new_tx(manager1, address, value)
        initial.weight = 25
        initial.update_hash()
        manager1.propagate_tx(initial, fails_silently=False)
        self.graphviz.labels[initial.hash] = 'initial'

        x = initial
        x = self.do_step(0, manager1, x)

        # Uncomment lines below to visualize the DAG and the blockchain.
        # dot = self.graphviz.dot()
        # dot.render('dot0')

    def test_two_conflicts_intertwined_multiple_times(self):
        manager1 = self.create_peer()
        manager1.allow_mining_without_peers()

        miner1 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        self.simulator.run(60)

        gen_tx1 = self.simulator.create_tx_generator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        self.simulator.run(300)
        gen_tx1.stop()

        # Our full node wallet has a callLater that checks for new utxos every 10 seconds.
        # If we don't run 10 seconds, the utxos generated on the create_tx_generator won't be available,
        # then we might get an insufficient fund error to create the next tx
        self.simulator.run(10)

        self.graphviz = GraphvizVisualizer(manager1.tx_storage, include_verifications=True, include_funds=True)

        address = manager1.wallet.get_unused_address(mark_as_used=False)
        value = 10
        initial = gen_new_tx(manager1, address, value)
        initial.weight = 25
        initial.update_hash()
        manager1.propagate_tx(initial, fails_silently=False)
        self.graphviz.labels[initial.hash] = 'initial'

        x = initial
        x = self.do_step(0, manager1, x)
        x = self.do_step(1, manager1, x)
        x = self.do_step(2, manager1, x)
        x = self.do_step(3, manager1, x)
        x = self.do_step(4, manager1, x)

        # Uncomment lines below to visualize the DAG and the blockchain.
        # dot = self.graphviz.dot()
        # dot.render('dot0')


class SyncV1ConsensusSimulatorTestCase(unittest.SyncV1Params, BaseConsensusSimulatorTestCase):
    __test__ = True


class SyncV2ConsensusSimulatorTestCase(unittest.SyncV2Params, BaseConsensusSimulatorTestCase):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeConsensusSimulatorTestCase(unittest.SyncBridgeParams, SyncV2ConsensusSimulatorTestCase):
    __test__ = True
