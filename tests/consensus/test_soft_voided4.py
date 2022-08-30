from hathor.conf import HathorSettings
from hathor.graphviz import GraphvizVisualizer
from hathor.simulator import FakeConnection
from tests import unittest
from tests.simulation.base import SimulatorTestCase
from tests.utils import add_custom_tx, gen_new_double_spending

settings = HathorSettings()


class BaseSoftVoidedTestCase(SimulatorTestCase):
    seed_config = 5988775361793628169

    def test_soft_voided(self):
        txA_hash = bytes.fromhex('1ae4ce163495279dafddca041b7c99abd71af55f29568746f3a20deead15f14d')
        txB_hash = bytes.fromhex('6343d6549f6743bd1718d92919f5dabf6705762953aaec2b14e68cb048b4207a')
        soft_voided_tx_ids = set([
            txA_hash,
            txB_hash,
        ])

        manager1 = self.create_peer(soft_voided_tx_ids=soft_voided_tx_ids)
        manager1.allow_mining_without_peers()

        miner1 = self.simulator.create_miner(manager1, hashpower=5e6)
        miner1.start()
        self.simulator.run(60)

        gen_tx1 = self.simulator.create_tx_generator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        self.simulator.run(300)

        manager2 = self.create_peer(soft_voided_tx_ids=soft_voided_tx_ids)
        manager2.soft_voided_tx_ids = soft_voided_tx_ids

        self.graphviz = GraphvizVisualizer(manager2.tx_storage, include_verifications=True, include_funds=True)

        conn12 = FakeConnection(manager1, manager2, latency=0.001)
        self.simulator.add_connection(conn12)

        miner2 = self.simulator.create_miner(manager2, hashpower=10e6)
        miner2.start()

        gen_tx2 = self.simulator.create_tx_generator(manager2, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx2.start()
        self.simulator.run(950)
        miner2.stop()
        gen_tx2.stop()

        txB = manager2.tx_storage.get_transaction(txB_hash)

        # Get the tx confirmed by the soft voided that will be voided
        tx_base = manager2.tx_storage.get_transaction(txB.parents[0])
        txC = gen_new_double_spending(manager2, use_same_parents=False, tx=tx_base)
        txC.weight = 25
        txC.parents = tx_base.parents
        txC.update_hash()
        self.graphviz.labels[txC.hash] = 'txC'
        self.assertTrue(manager2.propagate_tx(txC, fails_silently=False))
        metaC = txC.get_metadata()
        self.assertIsNone(metaC.voided_by)

        meta_base = tx_base.get_metadata()
        self.assertEqual(meta_base.voided_by, {tx_base.hash})

        # Create 2 blocks confirming C in order to keep this voidance when we add
        # the block confirming the soft voided tx
        blk1 = manager2.generate_mining_block()
        if txC.hash not in blk1.parents:
            blk1.parents[1] = txC.hash
        blk1.nonce = self.rng.getrandbits(32)
        blk1.update_hash()
        self.assertTrue(manager2.propagate_tx(blk1, fails_silently=False))
        blk1meta = blk1.get_metadata()
        self.assertIsNone(blk1meta.voided_by)

        blk2 = manager2.generate_mining_block()
        if txC.hash not in blk2.parents:
            blk2.parents[1] = txC.hash
        blk2.nonce = self.rng.getrandbits(32)
        blk2.update_hash()
        self.assertTrue(manager2.propagate_tx(blk2, fails_silently=False))
        blk2meta = blk2.get_metadata()
        self.assertIsNone(blk2meta.voided_by)

        # Create block that confirms soft voided
        blk3 = manager2.generate_mining_block()
        if txB.hash not in blk3.parents:
            blk3.parents[1] = txB.hash
        blk3.nonce = self.rng.getrandbits(32)
        blk3.update_hash()
        self.assertTrue(manager2.propagate_tx(blk3, fails_silently=False))
        blk3meta = blk3.get_metadata()

        self.simulator.run(10)
        txD = add_custom_tx(manager2, [(txC, 0)], base_parent=txB)

        # dot = self.graphviz.dot()
        # dot.render('test_soft_voided4')

        blk3meta = blk3.get_metadata()
        self.assertEqual(blk3meta.voided_by, {tx_base.hash, blk3meta.hash})
        metaD = txD.get_metadata()
        self.assertEqual(metaD.voided_by, {tx_base.hash})


class SyncV1SoftVoidedTestCase(unittest.SyncV1Params, BaseSoftVoidedTestCase):
    __test__ = True


class SyncV2SoftVoidedTestCase(unittest.SyncV2Params, BaseSoftVoidedTestCase):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeSoftVoidedTestCase(unittest.SyncBridgeParams, SyncV2SoftVoidedTestCase):
    __test__ = True
