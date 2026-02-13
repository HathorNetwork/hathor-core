from typing import Iterator

from hathor.graphviz import GraphvizVisualizer
from hathor.manager import HathorManager
from hathor.simulator import Simulator
from hathor.simulator.utils import gen_new_tx
from hathor.transaction import Block, Transaction
from hathor.types import VertexId
from hathor.wallet import HDWallet
from hathor_tests.simulation.base import SimulatorTestCase
from hathor_tests.utils import BURN_ADDRESS, add_custom_tx


class ConsensusSimulatorTestCase(SimulatorTestCase):
    seed_config = 5988775361793628169

    def assertValidConflictResolution(self, tx1: Transaction, tx2: Transaction) -> None:
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

    def do_step(self, i: int, manager1: HathorManager, tx_base: Transaction) -> Transaction:
        wallet = manager1.wallet
        assert isinstance(wallet, HDWallet)
        address = wallet.get_address(wallet.get_key_at_index(0))

        txA = add_custom_tx(manager1, [(tx_base, 0)], n_outputs=2, address=address)
        self.graphviz.labels[txA.hash] = f'txA-{i}'

        txB = add_custom_tx(manager1, [(txA, 0)], address=address)
        self.graphviz.labels[txB.hash] = f'txB-{i}'
        txC = add_custom_tx(manager1, [(txA, 1)], address=address)
        self.graphviz.labels[txC.hash] = f'txC-{i}'

        txD1 = add_custom_tx(manager1, [(txC, 0)], base_parent=tx_base, address=address)
        self.graphviz.labels[txD1.hash] = f'txD1-{i}'
        txF2 = add_custom_tx(manager1, [(txB, 0), (txD1, 0)], address=address)
        self.graphviz.labels[txF2.hash] = f'txF2-{i}'

        txD2 = add_custom_tx(manager1, [(txC, 0)], base_parent=tx_base, inc_timestamp=1, address=address)
        self.graphviz.labels[txD2.hash] = f'txD2-{i}'
        txE = add_custom_tx(manager1, [(txD2, 0)], base_parent=tx_base, address=address)
        self.graphviz.labels[txE.hash] = f'txE-{i}'

        txF1 = add_custom_tx(manager1, [(txB, 0)], base_parent=tx_base, address=address)
        self.graphviz.labels[txF1.hash] = f'txF1-{i}'

        if not self.skip_asserts:
            self.assertIn(txF1.hash, manager1.consensus_algorithm.soft_voided_tx_ids)
            self.assertIn(txF2.hash, manager1.consensus_algorithm.soft_voided_tx_ids)

        txG = add_custom_tx(manager1, [(txF2, 0)], base_parent=tx_base, address=address)
        self.graphviz.labels[txG.hash] = f'txG-{i}'

        txH = add_custom_tx(manager1, [(txF1, 0), (txG, 0)], address=address)
        self.graphviz.labels[txH.hash] = f'txH-{i}'

        print(f'!! txA-{i}: {txA.hash.hex()}')
        print(f'!! txB-{i}: {txB.hash.hex()}')
        print(f'!! txC-{i}: {txC.hash.hex()}', txC.outputs[0].script.hex())
        print(f'!! txD1-{i}: {txD1.hash.hex()}')
        from hathor.transaction.vertex_parser import vertex_serializer
        print(f'!! txD2-{i}: {txD2.hash.hex()}', vertex_serializer.serialize(txD2).hex())
        print(f'!! txE-{i}: {txE.hash.hex()}')

        print(f'!! txF1-{i}: {txF1.hash.hex()}')
        print(f'!! txF2-{i}: {txF2.hash.hex()}')

        if i == 0:
            self.txF1_0 = txF1
            self.txF2_0 = txF2
            self.txB_0 = txB
            self.txD1_0 = txD1

        self.txF_hashes.extend([txF1.hash, txF2.hash])

        self.assertValidConflictResolution(txD1, txD2)
        self.assertValidConflictResolution(txF1, txF2)

        return txH

    def gen_block(self, manager1: HathorManager, tx: Transaction, parent_block: Block | None = None) -> Block:
        parent_block_hash = parent_block.hash if parent_block else None
        block = manager1.generate_mining_block(parent_block_hash=parent_block_hash, address=BURN_ADDRESS)
        block.parents[1] = tx.hash
        block.timestamp = max(block.timestamp, tx.timestamp + 1)
        block.nonce = self.rng.getrandbits(32)
        block.update_hash()
        self.assertTrue(manager1.propagate_tx(block))
        return block

    def _run_test(self, simulator: Simulator, soft_voided_tx_ids: set[VertexId]) -> Iterator[None]:
        self.txF_hashes: list[VertexId] = []

        manager1 = self.create_peer(soft_voided_tx_ids=soft_voided_tx_ids, simulator=simulator)
        manager1.allow_mining_without_peers()

        miner1 = simulator.create_miner(manager1, hashpower=10e6)
        miner1.start()
        simulator.run(60)

        gen_tx1 = simulator.create_tx_generator(manager1, rate=3 / 60., hashpower=1e6, ignore_no_funds=True)
        gen_tx1.start()
        simulator.run(300)

        self.graphviz = GraphvizVisualizer(manager1.tx_storage, include_verifications=True, include_funds=True)

        assert manager1.wallet is not None
        address = manager1.wallet.get_unused_address(mark_as_used=False)
        value = 10
        initial = gen_new_tx(manager1, address, value)
        initial.weight = 25
        initial.update_hash()
        manager1.propagate_tx(initial)
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

        yield

        self.assertIsNone(b0.get_metadata().voided_by)
        self.assertIsNone(b1.get_metadata().voided_by)
        self.assertIsNone(b2.get_metadata().voided_by)
        self.assertIsNone(b3.get_metadata().voided_by)
        self.assertIsNone(b4.get_metadata().voided_by)
        self.assertIsNone(b5.get_metadata().voided_by)

        for tx in manager1.tx_storage.get_all_transactions():
            meta = tx.get_metadata()
            voided_by = meta.voided_by or set()
            if self._settings.SOFT_VOIDED_ID in voided_by:
                self.assertTrue({self._settings.SOFT_VOIDED_ID, tx.hash}.issubset(voided_by))

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

    def _get_txF_hashes(self) -> list[VertexId]:
        self.skip_asserts = True
        simulator = Simulator(seed=self.simulator.seed)
        simulator.start()

        try:
            it = self._run_test(simulator, set())
            next(it)
        finally:
            simulator.stop()
            self.skip_asserts = False

        return list(self.txF_hashes)

    def test_soft_voided(self) -> None:
        txF_hashes = self._get_txF_hashes()
        self.assertEqual(10, len(txF_hashes))
        soft_voided_tx_ids = set(txF_hashes)
        self.assertEqual(10, len(soft_voided_tx_ids))
        for _ in self._run_test(self.simulator, soft_voided_tx_ids):
            pass
