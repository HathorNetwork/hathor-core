from hathor.conf import HathorSettings
from hathor.graphviz import GraphvizVisualizer
from hathor.simulator import FakeConnection, Simulator
from tests import unittest
from tests.simulation.base import SimulatorTestCase
from tests.utils import add_custom_tx, gen_custom_tx, gen_new_tx

settings = HathorSettings()


class BaseSoftVoidedTestCase(SimulatorTestCase):
    seed_config = 5988775361793628169

    def assertNoParentsAreSoftVoided(self, tx):
        for h in tx.parents:
            tx2 = tx.storage.get_transaction(h)
            tx2_meta = tx2.get_metadata()
            tx2_voided_by = tx2_meta.voided_by or set()
            self.assertNotIn(settings.SOFT_VOIDED_ID, tx2_voided_by)

    def _run_test(self, simulator, soft_voided_tx_ids):
        manager1 = self.create_peer(soft_voided_tx_ids=soft_voided_tx_ids, simulator=simulator)
        manager1.allow_mining_without_peers()

        miner1 = simulator.create_miner(manager1, hashpower=5e6)
        miner1.start()
        simulator.run(60)

        gen_tx1 = simulator.create_tx_generator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        simulator.run(300)

        manager2 = self.create_peer(soft_voided_tx_ids=soft_voided_tx_ids, simulator=simulator)
        manager2.soft_voided_tx_ids = soft_voided_tx_ids

        graphviz = GraphvizVisualizer(manager2.tx_storage, include_verifications=True, include_funds=True)

        conn12 = FakeConnection(manager1, manager2, latency=0.001)
        simulator.add_connection(conn12)

        miner2 = simulator.create_miner(manager2, hashpower=10e6)
        miner2.start()

        gen_tx2 = simulator.create_tx_generator(manager2, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx2.start()

        for _ in gen_tx2.yield_until_find_a_transaction(max_steps=100):
            simulator.run(300)

        yield gen_tx2

        self.assertEqual(1, len(soft_voided_tx_ids))
        txA_hash = list(soft_voided_tx_ids)[0]

        simulator.run(300)
        miner2.stop()
        gen_tx2.stop()

        txA = manager2.tx_storage.get_transaction(txA_hash)
        metaA = txA.get_metadata()
        self.assertEqual({settings.SOFT_VOIDED_ID, txA.hash}, metaA.voided_by)
        graphviz.labels[txA.hash] = 'txA'

        txB = add_custom_tx(manager2, [(txA, 0)])
        metaB = txB.get_metadata()
        self.assertEqual({txA.hash}, metaB.voided_by)
        graphviz.labels[txB.hash] = 'txB'

        txD1 = add_custom_tx(manager2, [(txB, 0)])
        metaD1 = txD1.get_metadata()
        self.assertEqual({txA.hash}, metaD1.voided_by)
        graphviz.labels[txD1.hash] = 'txD1'

        blk1 = manager2.generate_mining_block()
        self.assertNoParentsAreSoftVoided(blk1)
        if txD1.hash not in blk1.parents:
            blk1.parents[1] = txD1.hash
        blk1.timestamp = txD1.timestamp + 1
        blk1.nonce = self.rng.getrandbits(32)
        blk1.update_hash()
        self.assertTrue(manager2.propagate_tx(blk1, fails_silently=False))
        blk1meta = blk1.get_metadata()
        self.assertIsNone(blk1meta.voided_by)
        graphviz.labels[blk1.hash] = 'blk1'

        simulator.run(10)
        address = manager2.wallet.get_unused_address(mark_as_used=True)
        txC = gen_new_tx(manager2, address, 6400)
        if txD1.hash not in txC.parents:
            txC.parents[1] = txD1.hash
        txC.weight = 25
        txC.update_hash()
        manager2.propagate_tx(txC, fails_silently=False)
        metaC = txC.get_metadata()
        self.assertIsNone(metaC.voided_by)
        graphviz.labels[txC.hash] = 'txC'

        txD2 = gen_custom_tx(manager2, [(txB, 0)])
        txD2.timestamp = txD1.timestamp + 2
        txD2.update_hash()
        manager2.propagate_tx(txD2, fails_silently=False)
        graphviz.labels[txD2.hash] = 'txD2'

        blk1meta = blk1.get_metadata()
        self.assertIsNone(blk1meta.voided_by)
        metaC = txC.get_metadata()
        self.assertIsNone(metaC.voided_by)

        # Uncomment lines below to visualize the DAG and the blockchain.
        # dot = graphviz.dot()
        # dot.render('test_soft_voided3')

    def _get_txA_hash(self):
        simulator = Simulator(seed=self.simulator.seed)
        simulator.start()

        try:
            it = self._run_test(simulator, set())
            tx_gen = next(it)
            txA_hash = tx_gen.latest_transactions[0]
        finally:
            simulator.stop()

        return txA_hash

    def test_soft_voided(self):
        txA_hash = self._get_txA_hash()
        soft_voided_tx_ids = set([
            txA_hash,
        ])
        for _ in self._run_test(self.simulator, soft_voided_tx_ids):
            pass


class SyncV1SoftVoidedTestCase(unittest.SyncV1Params, BaseSoftVoidedTestCase):
    __test__ = True


class SyncV2SoftVoidedTestCase(unittest.SyncV2Params, BaseSoftVoidedTestCase):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeSoftVoidedTestCase(unittest.SyncBridgeParams, SyncV2SoftVoidedTestCase):
    __test__ = True
