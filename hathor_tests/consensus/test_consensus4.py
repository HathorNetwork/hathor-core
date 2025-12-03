from hathor.graphviz import GraphvizVisualizer
from hathor.manager import HathorManager
from hathor.transaction import Block
from hathor.types import VertexId
from hathor_tests.simulation.base import SimulatorTestCase
from hathor_tests.utils import gen_custom_tx


class ConsensusSimulatorTestCase(SimulatorTestCase):
    def create_chain(
        self,
        manager: HathorManager,
        first_parent_block_hash: VertexId,
        length: int,
        prefix: str,
        tx_parents: list[VertexId] | None = None
    ) -> list[Block]:
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

    def test_conflict_with_parent_tx(self) -> None:
        manager1 = self.create_peer()
        manager1.allow_mining_without_peers()

        self.graphviz = GraphvizVisualizer(manager1.tx_storage, include_verifications=True, include_funds=True)

        b1 = manager1.generate_mining_block()
        b1.nonce = self.rng.getrandbits(32)
        b1.update_hash()
        self.graphviz.labels[b1.hash] = 'b1'
        self.assertTrue(manager1.propagate_tx(b1))
        self.simulator.run(10)

        A_list = self.create_chain(manager1, b1.hash, 15, 'A-')

        tx1 = gen_custom_tx(manager1, [(A_list[0], 0)])
        tx1.parents = manager1.get_new_tx_parents(tx1.timestamp)
        tx1.update_hash()
        self.graphviz.labels[tx1.hash] = 'tx1'
        self.assertTrue(manager1.propagate_tx(tx1))

        tx2 = gen_custom_tx(manager1, [(tx1, 0)])
        tx2.parents = manager1.get_new_tx_parents(tx2.timestamp)
        tx2.update_hash()
        self.graphviz.labels[tx2.hash] = 'tx2'
        self.assertTrue(manager1.propagate_tx(tx2))

        tx31 = gen_custom_tx(manager1, [(tx2, 0)])
        self.graphviz.labels[tx31.hash] = 'tx3-1'
        self.assertTrue(manager1.propagate_tx(tx31))

        tx32 = gen_custom_tx(manager1, [(tx2, 0)])
        tx32.parents = [tx31.hash, tx2.hash]
        tx32.timestamp = tx31.timestamp + 1
        tx32.update_hash()
        self.graphviz.labels[tx32.hash] = 'tx3-2'
        self.assertTrue(manager1.propagate_tx(tx32))

        self.assertIsNone(tx31.get_metadata().voided_by)
        self.assertEqual({tx32.hash}, tx32.get_metadata().voided_by)

        self.create_chain(manager1, b1.hash, 20, 'B-', tx_parents=b1.parents[1:])

        self.assertEqual({A_list[0].hash, tx31.hash}, tx31.get_metadata().voided_by)
        self.assertEqual({A_list[0].hash, tx31.hash, tx32.hash}, tx32.get_metadata().voided_by)

        # Uncomment lines below to visualize the DAG and the blockchain.
        # dot = self.graphviz.dot()
        # dot.render('dot0')
