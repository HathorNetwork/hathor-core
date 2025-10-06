from typing import Iterator

from hathor.graphviz import GraphvizVisualizer
from hathor.simulator import FakeConnection, RandomTransactionGenerator, Simulator
from hathor.simulator.trigger import StopAfterNTransactions
from hathor.simulator.utils import gen_new_tx
from hathor.transaction import Block
from hathor.types import VertexId
from hathor_tests.simulation.base import SimulatorTestCase
from hathor_tests.utils import add_custom_tx


class SoftVoidedTestCase(SimulatorTestCase):
    seed_config = 2

    def assertNoParentsAreSoftVoided(self, tx: Block) -> None:
        assert tx.storage is not None
        for h in tx.parents:
            tx2 = tx.storage.get_transaction(h)
            tx2_meta = tx2.get_metadata()
            tx2_voided_by = tx2_meta.voided_by or set()
            self.assertNotIn(self._settings.SOFT_VOIDED_ID, tx2_voided_by)

    def _run_test(
        self,
        simulator: Simulator,
        soft_voided_tx_ids: set[VertexId]
    ) -> Iterator[RandomTransactionGenerator]:
        manager1 = self.create_peer(soft_voided_tx_ids=soft_voided_tx_ids, simulator=simulator)
        manager1.allow_mining_without_peers()

        miner1 = simulator.create_miner(manager1, hashpower=5e6)
        miner1.start()
        simulator.run(60)

        gen_tx1 = simulator.create_tx_generator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        simulator.run(300)

        manager2 = self.create_peer(soft_voided_tx_ids=soft_voided_tx_ids, simulator=simulator)

        graphviz = GraphvizVisualizer(manager2.tx_storage, include_verifications=True, include_funds=True)

        conn12 = FakeConnection(manager1, manager2, latency=0.001)
        simulator.add_connection(conn12)

        miner2 = simulator.create_miner(manager2, hashpower=10e6)
        miner2.start()
        gen_tx2 = simulator.create_tx_generator(manager2, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx2.start()

        trigger = StopAfterNTransactions(gen_tx2, quantity=1)
        self.assertTrue(simulator.run(7200, trigger=trigger))

        yield gen_tx2

        self.assertEqual(1, len(soft_voided_tx_ids))
        txA_hash = list(soft_voided_tx_ids)[0]

        simulator.run(300)

        txA = manager2.tx_storage.get_transaction(txA_hash)
        metaA = txA.get_metadata()
        self.assertEqual({self._settings.SOFT_VOIDED_ID, txA.hash}, metaA.voided_by)
        graphviz.labels[txA.hash] = 'txA'

        txB = add_custom_tx(manager2, [(txA, 0)])
        metaB = txB.get_metadata()
        self.assertEqual({txA.hash}, metaB.voided_by)
        graphviz.labels[txB.hash] = 'txB'

        txD1 = add_custom_tx(manager2, [(txB, 0)])
        metaD1 = txD1.get_metadata()
        self.assertEqual({txA.hash}, metaD1.voided_by)
        graphviz.labels[txD1.hash] = 'txD1'

        txD2 = add_custom_tx(manager2, [(txB, 0)], inc_timestamp=1)
        metaD2 = txD2.get_metadata()
        self.assertEqual({txA.hash, txD2.hash}, metaD2.voided_by)
        graphviz.labels[txD2.hash] = 'txD2'
        metaD1 = txD1.get_metadata()
        self.assertEqual({txA.hash, txD1.hash}, metaD1.voided_by)

        assert manager2.wallet is not None
        address = manager2.wallet.get_unused_address(mark_as_used=False)
        value = 1
        txC = gen_new_tx(manager2, address, value)
        txC.parents[0] = txA.hash
        txC.timestamp = max(txC.timestamp, txA.timestamp + 1)
        txC.weight = 25
        txC.update_hash()
        self.assertTrue(manager2.propagate_tx(txC))
        metaC = txC.get_metadata()
        self.assertIsNone(metaC.voided_by)
        graphviz.labels[txC.hash] = 'txC'

        blk1 = manager2.generate_mining_block()
        self.assertNoParentsAreSoftVoided(blk1)
        blk1.parents[1] = txA.hash
        blk1.nonce = self.rng.getrandbits(32)
        blk1.update_hash()
        self.assertTrue(manager2.propagate_tx(blk1))
        blk1meta = blk1.get_metadata()
        self.assertIsNone(blk1meta.voided_by)
        graphviz.labels[blk1.hash] = 'b1'

        blk2 = manager2.generate_mining_block()
        self.assertNoParentsAreSoftVoided(blk2)
        if txD1.hash not in blk2.parents:
            blk2.parents[1] = txD1.hash
        blk2.nonce = self.rng.getrandbits(32)
        blk2.update_hash()
        self.assertTrue(manager2.propagate_tx(blk2))
        blk2meta = blk2.get_metadata()
        self.assertIsNone(blk2meta.voided_by)
        graphviz.labels[blk2.hash] = 'b2'

        blk3 = manager2.generate_mining_block()
        self.assertNoParentsAreSoftVoided(blk3)
        blk3.parents[1] = txD2.hash
        blk3.nonce = self.rng.getrandbits(32)
        blk3.update_hash()
        self.assertTrue(manager2.propagate_tx(blk3))
        blk3meta = blk3.get_metadata()
        self.assertIsNone(blk3meta.voided_by)
        graphviz.labels[blk3.hash] = 'b3'

        for tx in manager1.tx_storage.get_all_transactions():
            meta = tx.get_metadata()
            voided_by = meta.voided_by or set()
            if self._settings.SOFT_VOIDED_ID in voided_by:
                self.assertTrue({self._settings.SOFT_VOIDED_ID, tx.hash}.issubset(voided_by))

        # Uncomment lines below to visualize the DAG and the blockchain.
        # dot = graphviz.dot()
        # dot.render('dot0')

    def _get_txA_hash(self) -> VertexId:
        simulator = Simulator(seed=self.simulator.seed)
        simulator.start()

        try:
            it = self._run_test(simulator, set())
            gen_tx = next(it)
            txA_hash = gen_tx.latest_transactions[0]
        finally:
            simulator.stop()

        return txA_hash

    def test_soft_voided(self) -> None:
        txA_hash = self._get_txA_hash()
        soft_voided_tx_ids = set([
            txA_hash,
        ])
        for _ in self._run_test(self.simulator, soft_voided_tx_ids):
            pass
