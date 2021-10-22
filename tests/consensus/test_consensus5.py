from hathor.graphviz import GraphvizVisualizer
from tests import unittest
from tests.simulation.base import SimulatorTestCase
from tests.utils import gen_custom_tx


class BaseConsensusSimulatorTestCase(SimulatorTestCase):

    def create_chain(self, manager, first_parent_block_hash, length, prefix, tx_parents=None):
        current = first_parent_block_hash
        v = []
        for i in range(length):
            blk = manager.generate_mining_block(parent_block_hash=current)
            blk.weight = min(50.0, blk.weight)
            blk.nonce = self.rng.getrandbits(32)
            if tx_parents:
                blk.parents[1:] = tx_parents
            blk.update_hash()
            self.graphviz.labels[blk.hash] = f'{prefix}b{i}'
            self.assertTrue(manager.propagate_tx(blk))
            self.simulator.run(10)
            v.append(blk)
            current = blk.hash
        return v

    def test_conflict_with_parent_tx(self):
        manager1 = self.create_peer()
        manager1.allow_mining_without_peers()

        self.graphviz = GraphvizVisualizer(manager1.tx_storage, include_verifications=True, include_funds=True)

        b1 = manager1.generate_mining_block()
        b1.nonce = self.rng.getrandbits(32)
        b1.update_hash()
        self.graphviz.labels[b1.hash] = 'b1'
        self.assertTrue(manager1.propagate_tx(b1))
        self.simulator.run(10)

        self.create_chain(manager1, b1.hash, 20, '')

        txA1 = gen_custom_tx(manager1, [(b1, 0)])
        self.graphviz.labels[txA1.hash] = 'txA1'
        self.assertTrue(manager1.propagate_tx(txA1))
        self.simulator.run(10)

        txA2 = gen_custom_tx(manager1, [(b1, 0)])
        self.graphviz.labels[txA2.hash] = 'txA2'
        self.assertTrue(manager1.propagate_tx(txA2))
        self.simulator.run(10)

        b2 = manager1.generate_mining_block()
        b2.weight = max(b2.weight, 40)
        b2.parents[1:] = [txA1.parents[0], txA1.hash]
        b2.nonce = self.rng.getrandbits(32)
        b2.update_hash()
        self.graphviz.labels[b2.hash] = 'b2'
        self.assertTrue(manager1.propagate_tx(b2, fails_silently=False))
        self.simulator.run(10)

        self.assertIsNone(txA1.get_metadata().voided_by)
        self.assertEqual({txA2.hash}, txA2.get_metadata().voided_by)

        txC1 = gen_custom_tx(manager1, [(txA2, 0)])
        self.graphviz.labels[txC1.hash] = 'txC1'
        self.assertTrue(manager1.propagate_tx(txC1))

        txC2 = gen_custom_tx(manager1, [(txA2, 0)])
        self.graphviz.labels[txC2.hash] = 'txC2'
        self.assertTrue(manager1.propagate_tx(txC2))

        self.assertEqual({txA2.hash, txC1.hash}, txC1.get_metadata().voided_by)
        self.assertEqual({txA2.hash, txC2.hash}, txC2.get_metadata().voided_by)

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
