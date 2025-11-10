from typing import Iterator

from hathor.graphviz import GraphvizVisualizer
from hathor.simulator import FakeConnection, RandomTransactionGenerator, Simulator
from hathor.simulator.trigger import StopAfterNTransactions
from hathor.simulator.utils import gen_new_double_spending
from hathor.transaction import Transaction
from hathor.types import VertexId
from hathor_tests.simulation.base import SimulatorTestCase
from hathor_tests.utils import add_custom_tx


class SoftVoidedTestCase(SimulatorTestCase):
    seed_config = 5988775361793628169

    def _run_test(
        self,
        simulator: Simulator,
        soft_voided_tx_ids: list[VertexId]
    ) -> Iterator[RandomTransactionGenerator]:
        manager1 = self.create_peer(soft_voided_tx_ids=set(soft_voided_tx_ids), simulator=simulator)
        manager1.allow_mining_without_peers()

        miner1 = simulator.create_miner(manager1, hashpower=5e6)
        miner1.start()
        simulator.run(60)

        gen_tx1 = simulator.create_tx_generator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        simulator.run(300)
        gen_tx1.stop()

        manager2 = self.create_peer(soft_voided_tx_ids=set(soft_voided_tx_ids), simulator=simulator)

        self.graphviz = GraphvizVisualizer(manager2.tx_storage, include_verifications=True, include_funds=True)

        conn12 = FakeConnection(manager1, manager2, latency=0.001)
        simulator.add_connection(conn12)

        miner2 = simulator.create_miner(manager2, hashpower=10e6)
        miner2.start()

        gen_tx2 = simulator.create_tx_generator(manager2, rate=10 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx2.start()

        trigger = StopAfterNTransactions(gen_tx2, quantity=1)
        self.assertTrue(simulator.run(7200, trigger=trigger))

        yield gen_tx2

        simulator.run(300)

        yield gen_tx2

        miner1.stop()
        miner2.stop()
        simulator.run(300)

        yield gen_tx2

        gen_tx2.stop()

        assert isinstance(soft_voided_tx_ids, list)
        self.assertEqual(2, len(soft_voided_tx_ids))
        txA_hash = soft_voided_tx_ids[0]
        txB_hash = soft_voided_tx_ids[1]
        self.graphviz.labels[txA_hash] = 'txA'
        self.graphviz.labels[txB_hash] = 'txB'

        txB = manager2.tx_storage.get_transaction(txB_hash)
        assert isinstance(txB, Transaction)

        # Get the tx confirmed by the soft voided that will be voided
        tx_base = manager2.tx_storage.get_transaction(txB.parents[0])
        assert isinstance(tx_base, Transaction)
        txC = gen_new_double_spending(manager2, use_same_parents=False, tx=tx_base)
        self.graphviz.labels[tx_base.hash] = 'tx_base'
        txC.weight = 30
        txC.parents = tx_base.parents
        txC.update_hash()
        self.graphviz.labels[txC.hash] = 'txC'
        self.assertTrue(manager2.propagate_tx(txC))
        metaC = txC.get_metadata()
        self.assertIsNone(metaC.voided_by)

        meta_base = tx_base.get_metadata()
        self.assertEqual(meta_base.voided_by, {tx_base.hash})

        # Create 2 blocks confirming C in order to keep this voidance when we add
        # the block confirming the soft voided tx
        blk1 = manager2.generate_mining_block()
        if txC.hash not in blk1.parents:
            blk1.parents[1] = txC.hash
            blk1.update_timestamp(int(manager2.reactor.seconds()))
        blk1.nonce = self.rng.getrandbits(32)
        blk1.update_hash()

        # Uncomment lines below to visualize the DAG and the blockchain.
        # dot = self.graphviz.dot()
        # dot.render('dot0')

        self.assertTrue(manager2.propagate_tx(blk1))
        blk1meta = blk1.get_metadata()
        self.graphviz.labels[blk1.hash] = 'blk1'
        self.assertIsNone(blk1meta.voided_by)

        blk2 = manager2.generate_mining_block()
        if txC.hash not in blk2.parents:
            blk2.parents[1] = txC.hash
            blk2.update_timestamp(int(manager2.reactor.seconds()))
        blk2.nonce = self.rng.getrandbits(32)
        blk2.update_hash()
        self.assertTrue(manager2.propagate_tx(blk2))
        blk2meta = blk2.get_metadata()
        self.graphviz.labels[blk2.hash] = 'blk2'
        self.assertIsNone(blk2meta.voided_by)

        # Create block that confirms soft voided
        blk3 = manager2.generate_mining_block()
        if txB.hash not in blk3.parents:
            blk3.parents[1] = txB.hash
        blk3.nonce = self.rng.getrandbits(32)
        blk3.update_hash()
        self.assertTrue(manager2.propagate_tx(blk3))
        blk3meta = blk3.get_metadata()
        self.graphviz.labels[blk3.hash] = 'blk3'

        simulator.run(10)
        txD = add_custom_tx(manager2, [(txC, 0)], base_parent=txB)
        self.graphviz.labels[txD.hash] = 'txD'

        blk3meta = blk3.get_metadata()
        self.assertEqual(blk3meta.voided_by, {tx_base.hash, blk3meta.hash})
        metaD = txD.get_metadata()
        self.assertEqual(metaD.voided_by, {tx_base.hash})

    def _get_txA_hash(self) -> VertexId:
        simulator = Simulator(seed=self.simulator.seed)
        simulator.start()

        try:
            it = self._run_test(simulator, [])
            gen_tx = next(it)
            txA_hash = gen_tx.latest_transactions[0]
        finally:
            simulator.stop()

        return txA_hash

    def _get_txB_hash(self, txA_hash: VertexId) -> VertexId:
        simulator = Simulator(seed=self.simulator.seed)
        simulator.start()

        try:
            it = self._run_test(simulator, [txA_hash])
            _ = next(it)
            _ = next(it)
            gen_tx = next(it)
            txB_hash = gen_tx.latest_transactions[0]
        finally:
            simulator.stop()

        return txB_hash

    def test_soft_voided(self) -> None:
        txA_hash = self._get_txA_hash()
        txB_hash = self._get_txB_hash(txA_hash)
        self.assertNotEqual(txA_hash, txB_hash)
        soft_voided_tx_ids = [
            txA_hash,
            txB_hash,
        ]
        for _ in self._run_test(self.simulator, soft_voided_tx_ids):
            pass
