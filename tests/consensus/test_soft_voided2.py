from hathor.conf import HathorSettings
from hathor.graphviz import GraphvizVisualizer
from tests import unittest
from tests.simulation.base import SimulatorTestCase
from tests.utils import add_custom_tx, gen_new_tx

settings = HathorSettings()


class BaseConsensusSimulatorTestCase(SimulatorTestCase):
    seed_config = 5988775361793628169

    def assertValidConflictResolution(self, tx1, tx2):
        meta1 = tx1.get_metadata()
        meta2 = tx2.get_metadata()

        s1 = set()
        for txin in tx1.inputs:
            s1.add((txin.tx_id, txin.index))
        s2 = set()
        for txin in tx2.inputs:
            s2.add((txin.tx_id, txin.index))
        self.assertTrue(s1 & s2)

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

        txD2 = add_custom_tx(manager1, [(txC, 0)], base_parent=tx_base)
        self.graphviz.labels[txD2.hash] = f'txD2-{i}'
        txE = add_custom_tx(manager1, [(txD2, 0)], base_parent=tx_base)
        self.graphviz.labels[txE.hash] = f'txE-{i}'

        txF1 = add_custom_tx(manager1, [(txB, 0)], base_parent=tx_base)
        self.graphviz.labels[txF1.hash] = f'txF1-{i}'

        self.assertIn(txF1.hash, manager1.soft_voided_tx_ids)
        self.assertIn(txF2.hash, manager1.soft_voided_tx_ids)

        txG = add_custom_tx(manager1, [(txF2, 0)], base_parent=tx_base)
        self.graphviz.labels[txG.hash] = f'txG-{i}'

        txH = add_custom_tx(manager1, [(txF1, 0), (txG, 0)])
        self.graphviz.labels[txH.hash] = f'txH-{i}'

        print(f'!! txF1-{i}: {txF1.hash.hex()}')
        print(f'!! txF2-{i}: {txF2.hash.hex()}')

        if i == 0:
            self.txF1_0 = txF1
            self.txF2_0 = txF2
            self.txB_0 = txB
            self.txD1_0 = txD1

        self.assertValidConflictResolution(txD1, txD2)
        self.assertValidConflictResolution(txF1, txF2)

        return txH

    def gen_block(self, manager1, tx, parent_block=None):
        parent_block_hash = parent_block.hash if parent_block else None
        block = manager1.generate_mining_block(parent_block_hash=parent_block_hash)
        block.parents[1] = tx.hash
        block.timestamp = max(block.timestamp, tx.timestamp + 1)
        block.nonce = self.rng.getrandbits(32)
        block.update_hash()
        self.assertTrue(manager1.propagate_tx(block, fails_silently=False))
        return block

    def test_soft_voided(self):
        soft_voided_tx_ids = set([
            bytes.fromhex('30d49cf336ceb8528a918bed25b729febd3ebc3a8449d5e840aac865d0ca407f'),
            bytes.fromhex('875ef2cdf7405f82f20e0ba115cd2fe07d8c60c50f763f7c48e8d673f56ff4e4'),
            bytes.fromhex('ef0b5e356b82253c8b0f7f078396bd435605dc297b38af3d9623b88ffab43b41'),
            bytes.fromhex('aba55041658213b0bfda880045e5a321cb3d0a88cffa2833e620a2ed1ba27451'),
            bytes.fromhex('43f1782cc7d5702378d067daefea0460cd1976e5479e17accb6f412be8d26ff5'),
            bytes.fromhex('24fe23d0128c85bc149963ff904aefe1c11b44b0e0cddad344b308b34d1dbac8'),
            bytes.fromhex('a6b7b21e4020a70d77fd7467184c65bfb2e4443a0b465b6ace05c1b11b82355b'),
            bytes.fromhex('982e9a2a3f0b1d22eead5ca8cf9a86a5d9edd981ac06f977245a2e664a752e5f'),
            bytes.fromhex('b6cddd95fe02c035fde820add901545662c7b3ae85010cde5914b86cb0a6505e'),
            bytes.fromhex('3a84cff789d3263fea4da636da5c54cb0981a4a0caec1579037a4fa06457f8f3'),
        ])
        manager1 = self.create_peer(soft_voided_tx_ids=soft_voided_tx_ids)
        manager1.allow_mining_without_peers()

        miner1 = self.simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        self.simulator.run(60)

        gen_tx1 = self.simulator.create_tx_generator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        self.simulator.run(300)

        self.graphviz = GraphvizVisualizer(manager1.tx_storage, include_verifications=True, include_funds=True)

        address = manager1.wallet.get_unused_address(mark_as_used=False)
        value = 10
        initial = gen_new_tx(manager1, address, value)
        initial.weight = 25
        initial.update_hash()
        manager1.propagate_tx(initial, fails_silently=False)
        self.graphviz.labels[initial.hash] = 'initial'

        x = initial
        b0 = self.gen_block(manager1, x)
        self.graphviz.labels[b0.hash] = 'b0'

        x = self.do_step(0, manager1, x)
        b1 = self.gen_block(manager1, x, parent_block=b0)
        self.graphviz.labels[b1.hash] = 'b1'

        x = self.do_step(1, manager1, x)
        b2 = self.gen_block(manager1, x, parent_block=b1)
        self.graphviz.labels[b2.hash] = 'b2'

        x = self.do_step(2, manager1, x)
        b3 = self.gen_block(manager1, x, parent_block=b2)
        self.graphviz.labels[b3.hash] = 'b3'

        x = self.do_step(3, manager1, x)
        b4 = self.gen_block(manager1, x, parent_block=b3)
        self.graphviz.labels[b4.hash] = 'b4'

        x = self.do_step(4, manager1, x)
        b5 = self.gen_block(manager1, x, parent_block=b4)
        self.graphviz.labels[b5.hash] = 'b5'

        self.assertIsNone(b0.get_metadata().voided_by)
        self.assertIsNone(b1.get_metadata().voided_by)
        self.assertIsNone(b2.get_metadata().voided_by)
        self.assertIsNone(b3.get_metadata().voided_by)
        self.assertIsNone(b4.get_metadata().voided_by)
        self.assertIsNone(b5.get_metadata().voided_by)

        for tx in manager1.tx_storage.get_all_transactions():
            meta = tx.get_metadata()
            voided_by = meta.voided_by or set()
            if settings.SOFT_VOIDED_ID in voided_by:
                self.assertTrue({settings.SOFT_VOIDED_ID, tx.hash}.issubset(voided_by))

        txF1 = self.txF1_0
        txF2 = self.txF2_0

        txB = self.txB_0
        txB_meta = txB.get_metadata()
        txB_spent_list = txB_meta.spent_outputs[0]
        self.assertEqual(set(txB_spent_list), {txF1.hash, txF2.hash})
        self.assertIsNone(txB_meta.get_output_spent_by(0))

        txD1 = self.txD1_0
        txD1_meta = txD1.get_metadata()
        txD1_spent_list = txD1_meta.spent_outputs[0]
        self.assertEqual([txF2.hash], txD1_spent_list)
        self.assertIsNone(txD1_meta.get_output_spent_by(0))

        # import pudb; pudb.set_trace()

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
