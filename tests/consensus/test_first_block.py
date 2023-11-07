from tests import unittest


class FirstBlockTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = True

    def setUp(self) -> None:
        super().setUp()

        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        cpu_mining_service = SimulatorCpuMiningService()

        builder = self.get_builder() \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(cpu_mining_service)

        self.manager = self.create_peer_from_builder(builder)
        self.dag_builder = self.get_dag_builder(self.manager)

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

        for node, vertex in artifacts.list:
            self.manager.on_new_tx(vertex, fails_silently=False)

        b31 = artifacts.by_name['b31'].vertex
        b32 = artifacts.by_name['b32'].vertex
        b33 = artifacts.by_name['b33'].vertex

        tx10 = artifacts.by_name['tx10'].vertex
        tx20 = artifacts.by_name['tx20'].vertex
        tx30 = artifacts.by_name['tx30'].vertex
        tx40 = artifacts.by_name['tx40'].vertex
        tx41 = artifacts.by_name['tx41'].vertex
        tx42 = artifacts.by_name['tx42'].vertex
        tx43 = artifacts.by_name['tx43'].vertex
        tx50 = artifacts.by_name['tx50'].vertex

        self.assertEqual(tx10.get_metadata().first_block, b31.hash)

        self.assertEqual(tx30.get_metadata().first_block, b32.hash)
        self.assertEqual(tx43.get_metadata().first_block, b32.hash)

        self.assertEqual(tx50.get_metadata().first_block, b33.hash)
        self.assertEqual(tx20.get_metadata().first_block, b33.hash)
        self.assertEqual(tx40.get_metadata().first_block, b33.hash)
        self.assertEqual(tx41.get_metadata().first_block, b33.hash)
        self.assertEqual(tx42.get_metadata().first_block, b33.hash)
