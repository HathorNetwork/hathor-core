from hathor.nanocontracts.sorter.random_sorter import NCBlockSorter
from hathor.transaction import Transaction
from hathor.types import VertexId
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class NCBlockSorterTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        self.nodes = {}
        for i in range(100):
            self.nodes[i] = VertexId(f'{i}'.encode('ascii'))

        self.nc_nodes = {}
        for i in range(99):
            self.nc_nodes[i] = VertexId(f'nc-{i}'.encode('ascii'))

    def test_all_independent(self) -> None:
        sorter = NCBlockSorter(set(self.nodes.values()))
        for node in self.nodes.values():
            sorter.get_node(node)

        seed = self.rng.randbytes(32)
        order = sorter.copy().generate_random_topological_order(seed)
        self.assertEqual(len(self.nodes), len(set(order)))

        order2 = sorter.copy().generate_random_topological_order(seed)
        self.assertEqual(order, order2)

        # There are n! permutations.
        # Therefore, the probability of getting the same order is 1/100!, which is around 1e-158.
        for _ in range(100):
            seed2 = self.rng.randbytes(32)
            order2 = sorter.copy().generate_random_topological_order(seed2)
            self.assertNotEqual(order, order2)

    def test_single_one_step_dependencies(self) -> None:
        sorter = NCBlockSorter(set(self.nc_nodes.values()))

        # Generate the following graph:
        # 0 -> NC0 -> 1 -> NC1 -> 2 -> NC2 -> 3 -> ...
        for i in range(len(self.nodes) - 1):
            sorter.add_edge(self.nodes[i], self.nc_nodes[i])
            sorter.add_edge(self.nc_nodes[i], self.nodes[i + 1])

        seed = self.rng.randbytes(32)
        order = sorter.copy().generate_random_topological_order(seed)
        self.assertEqual(set(self.nc_nodes.values()), set(order))

        # There's only one valid order. So it must return the same order for any seed.
        for _ in range(100):
            seed2 = self.rng.randbytes(32)
            order2 = sorter.copy().generate_random_topological_order(seed2)
            self.assertEqual(order, order2)

    def test_single_long_dependencies(self) -> None:
        sorter = NCBlockSorter(set(self.nc_nodes.values()))

        # Generate the following graph:
        # 0 -> NC0 -> 1 -> 2 -> 3 -> 4 -> NC4 -> 5 -> 6 -> 7 -> 8 -> NC8 -> ...
        for i in range(len(self.nodes) - 1):
            if i % 4 == 0:
                sorter.add_edge(self.nodes[i], self.nc_nodes[i])
                sorter.add_edge(self.nc_nodes[i], self.nodes[i + 1])
            else:
                sorter.add_edge(self.nodes[i], self.nodes[i + 1])

        seed = self.rng.randbytes(32)
        order = sorter.copy().generate_random_topological_order(seed)
        self.assertEqual(set(x for i, x in self.nc_nodes.items() if i % 4 == 0), set(order))

        # There's only one valid order. So it must return the same order for any seed.
        for _ in range(100):
            seed2 = self.rng.randbytes(32)
            order2 = sorter.copy().generate_random_topological_order(seed2)
            self.assertEqual(order, order2)

    def test_linear_multiple_dependencies(self) -> None:
        sorter = NCBlockSorter(set(self.nc_nodes.values()))
        sorter.add_edge(self.nc_nodes[0], self.nodes[1])
        sorter.add_edge(self.nodes[1], self.nodes[2])
        sorter.add_edge(self.nodes[2], self.nodes[3])
        sorter.add_edge(self.nodes[3], self.nodes[4])
        sorter.add_edge(self.nodes[4], self.nc_nodes[5])

        seed = self.rng.randbytes(32)
        order = sorter.copy().generate_random_topological_order(seed)
        self.assertEqual(order, [
            self.nc_nodes[5],
            self.nc_nodes[0],
        ])

    def test_grid_multiple_dependencies(self) -> None:
        sorter = NCBlockSorter(set(self.nc_nodes.values()))

        idx = 0
        n_layers = 10
        n_per_layer = 8
        layers: list[list[VertexId]] = []

        selected_nc_nodes = {1, 57, 75}

        for _ in range(n_layers):
            current = []
            for j in range(n_per_layer):
                if idx in selected_nc_nodes:
                    vertex_id = self.nc_nodes[idx]
                else:
                    vertex_id = self.nodes[idx]
                current.append(vertex_id)
                idx += 1

                _ = sorter.get_node(vertex_id)
                if layers:
                    previous = layers[-1]
                    if j > 0:
                        sorter.add_edge(previous[j - 1], vertex_id)
                    sorter.add_edge(previous[j], vertex_id)
            layers.append(current)

        seed = self.rng.randbytes(32)
        order = sorter.copy().generate_random_topological_order(seed)
        self.assertEqual(order, [
            self.nc_nodes[75],
            self.nc_nodes[57],
            self.nc_nodes[1],
        ])

        # There's only one valid order. So it must return the same order for any seed.
        for _ in range(100):
            seed2 = self.rng.randbytes(32)
            order2 = sorter.copy().generate_random_topological_order(seed2)
            self.assertEqual(order, order2)

    def test_dag_dependencies(self) -> None:
        builder = self.get_builder()
        builder.enable_nc_anti_mev()
        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)

        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..32]
            b30 < dummy

            nc1.nc_id = ocb1
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = nop()

            nc3.nc_id = nc1
            nc3.nc_method = nop()

            nc4.nc_id = nc1
            nc4.nc_method = nop()

            nc5.nc_id = nc1
            nc5.nc_method = nop()

            nc6.nc_id = nc1
            nc6.nc_method = nop()

            b31 --> ocb1  # OCB must be confirmed before being used to create a contract
            b31 < nc1
            nc1 <-- nc2 <-- b32

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"
            ocb1.ocb_code = ```
                from hathor import Blueprint, Context, export, public

                @export
                class MyBlueprint(Blueprint):
                    @public
                    def initialize(self, ctx: Context) -> None:
                        pass

                    @public
                    def nop(self, ctx: Context) -> None:
                        pass
            ```
        """)

        artifacts.propagate_with(manager)

        ocb1, nc1 = artifacts.get_typed_vertices(['ocb1', 'nc1'], Transaction)

        nc_others = []
        for i in range(2, 7):
            nc_others.append(artifacts.get_typed_vertex(f'nc{i}', Transaction))

        assert ocb1.get_metadata().voided_by is None
        assert nc1.get_metadata().voided_by is None

        for tx in nc_others:
            # TODO Assert the execution order.
            assert tx.get_metadata().voided_by is None
