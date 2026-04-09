from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class FirstBlockTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        cpu_mining_service = SimulatorCpuMiningService()

        builder = self.get_builder() \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(cpu_mining_service)

        self.manager = self.create_peer_from_builder(builder)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_first_block(self) -> None:
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]

            b30 < dummy

            tx10.out[0] <<< tx50
            tx20.out[0] <<< tx50
            tx30 <-- tx50
            tx40 <-- tx50

            tx41.out[0] <<< tx40
            tx42 <-- tx40
            tx43 <-- tx40

            b31 --> tx10

            b32 --> tx30
            b32 --> tx43

            b33 --> tx50
        """)

        artifacts.propagate_with(self.manager)

        b31, b32, b33 = artifacts.get_typed_vertices(['b31', 'b32', 'b33'], Block)
        txs = ['tx10', 'tx20', 'tx30', 'tx40', 'tx41', 'tx42', 'tx43', 'tx50']
        tx10, tx20, tx30, tx40, tx41, tx42, tx43, tx50 = artifacts.get_typed_vertices(txs, Transaction)

        self.assertEqual(tx10.get_metadata().first_block, b31.hash)

        self.assertEqual(tx30.get_metadata().first_block, b32.hash)
        self.assertEqual(tx43.get_metadata().first_block, b32.hash)

        self.assertEqual(tx50.get_metadata().first_block, b33.hash)
        self.assertEqual(tx20.get_metadata().first_block, b33.hash)
        self.assertEqual(tx40.get_metadata().first_block, b33.hash)
        self.assertEqual(tx41.get_metadata().first_block, b33.hash)
        self.assertEqual(tx42.get_metadata().first_block, b33.hash)
