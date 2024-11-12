from hathor.transaction import Block, Transaction
from hathor.nanocontracts import Blueprint, Context, NanoContract, public
from hathor.nanocontracts.types import NCAction, NCActionType, TokenUid
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from tests import unittest


class MyBlueprint(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context, initial: int) -> None:
        self.counter = initial

    @public
    def add(self, ctx: Context, value: int) -> int:
        self.counter += value
        return self.counter

    @public
    def sub(self, ctx: Context, value: int) -> int:
        self.counter -= value
        return self.counter


class DAGBuilderTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        cpu_mining_service = SimulatorCpuMiningService()

        builder = self.get_builder() \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(cpu_mining_service)

        self.manager = self.create_peer_from_builder(builder)
        self.nc_catalog = self.manager.tx_storage.nc_catalog
        self.dag_builder = self.get_dag_builder(self.manager)

    def test_one_tx(self) -> None:
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b1.out[0] <<< tx1
            b30 < tx1      # reward lock
            b40 --> tx1
        """)

        artifacts.propagate_with(self.manager)

        v_order = [node.name for node, _ in artifacts.list]

        b1, b40 = artifacts.get_typed_vertices(['b1', 'b40'], Block)
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)

        # blockchain genesis b[1..50]
        self.assertEqual(b1.parents[0], self._settings.GENESIS_BLOCK_HASH)
        for i in range(2, 51):
            prev = artifacts.by_name[f'b{i - 1}'].vertex
            cur = artifacts.by_name[f'b{i}'].vertex
            self.assertEqual(cur.parents[0], prev.hash)

        # b30 < tx1
        self.assertGreater(v_order.index('tx1'), v_order.index('b30'))

        # b1.out[0] <<< tx1
        self.assertEqual(tx1.inputs[0].tx_id, b1.hash)

        # b40 --> tx1
        self.assertEqual(tx1.get_metadata().first_block, b40.hash)

    def test_weight(self) -> None:
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            blockchain b37 c[1..1]
            b30 < dummy
            b50 < c1

            tx1.out[0] = 1 TKA

            TKA.weight = 31.8
            tx1.weight = 25.2
            c1.weight = 80.6
        """)

        artifacts.propagate_with(self.manager)

        c1, b38 = artifacts.get_typed_vertices(['c1', 'b38'], Block)
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        tka = artifacts.get_typed_vertex('TKA', TokenCreationTransaction)

        self.assertAlmostEqual(tka.weight, 31.8)
        self.assertAlmostEqual(tx1.weight, 25.2)
        self.assertAlmostEqual(c1.weight, 80.6)
        self.assertIsNotNone(b38.get_metadata().voided_by, b38)

    def test_spend_unspecified_utxo(self) -> None:
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy
            tx1.out[0] <<< tx2
        """)

        artifacts.propagate_with(self.manager)

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        self.assertEqual(len(tx1.outputs), 1)
        # the default filler fills unspecified utxos with 1 HTR
        self.assertEqual(tx1.outputs[0].value, 1)
        self.assertEqual(tx1.outputs[0].token_data, 0)

    def test_block_parents(self) -> None:
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b30 < dummy

            b32 --> tx1

            b34 --> tx2

            b36 --> tx3
            b36 --> tx4
        """)

        artifacts.propagate_with(self.manager)

        blocks = ['b30', 'b31', 'b32', 'b33', 'b34', 'b35', 'b36', 'b37']
        b0, b1, b2, b3, b4, b5, b6, b7 = artifacts.get_typed_vertices(blocks, Block)
        tx1, tx2, tx3, tx4 = artifacts.get_typed_vertices(['tx1', 'tx2', 'tx3', 'tx4'], Transaction)

        self.assertEqual(b2.parents[0], b1.hash)
        self.assertEqual(b3.parents[0], b2.hash)
        self.assertEqual(b4.parents[0], b3.hash)
        self.assertEqual(b5.parents[0], b4.hash)
        self.assertEqual(b6.parents[0], b5.hash)

        self.assertEqual(set(b1.parents[1:]), set(b0.parents[1:]))
        self.assertEqual(set(b3.parents[1:]), set(b2.parents[1:]))
        self.assertEqual(set(b5.parents[1:]), set(b4.parents[1:]))
        self.assertEqual(set(b7.parents[1:]), set(b6.parents[1:]))

        self.assertTrue(set(b2.parents[1:]).issubset([tx1.hash] + b1.parents[1:]))
        self.assertTrue(set(b4.parents[1:]).issubset([tx2.hash] + b3.parents[1:]))
        self.assertEqual(set(b6.parents[1:]), {tx3.hash, tx4.hash})

    def test_custom_token(self) -> None:
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b1.out[0] <<< tx1
            tx1.out[1] = 100 TKA
            b30 < tx1      # reward lock
            b30 < dummy    # reward lock
            b40 --> tx1
        """)

        artifacts.propagate_with(self.manager)

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        tka = artifacts.get_typed_vertex('TKA', TokenCreationTransaction)

        # TKA token creation transaction
        self.assertEqual(tka.token_name, 'TKA')
        self.assertEqual(tka.token_symbol, 'TKA')

        # tx1.out[1] = 100 TKA
        self.assertEqual(tx1.outputs[1].value, 100)
        self.assertEqual(tx1.get_token_uid(tx1.outputs[1].token_data), tka.hash)

    def test_big_dag(self) -> None:
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis a[0..30]
            blockchain a30 b[0..20]
            blockchain b4 c[0..10]

            a30 < dummy

            b11 --> tx1
            b11 --> tx2

            b14 --> tx1
            b14 --> tx3

            c3 --> tx1
            c3 --> tx2

            tx1 <-- tx2 <-- tx3

            tx3 --> tx5 --> tx6

            tx1.out[0] <<< tx2 tx3
            tx1.out[0] <<< tx4

            a0.out[0] <<< tx1

            tx1.out[0] = 100 HTR [wallet1]
            tx1.out[1] = 50 TK1  [wallet2]
            tx2.out[0] = 75 USDC [wallet1]

            USDC.out[0] = 100000 HTR

            b5 < c0 < c10 < b20
            b6 < tx3
            b16 < tx4
        """)

        artifacts.propagate_with(self.manager)

    def test_no_hash_conflict(self) -> None:
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..33]

            b30 < dummy

            tx10.out[0] <<< tx20 tx30 tx40
        """)
        artifacts.propagate_with(self.manager)

    def test_propagate_with(self) -> None:
        tx_storage = self.manager.tx_storage
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..10]
            b10 < dummy
            tx1 <-- tx2
        ''')

        artifacts.propagate_with(self.manager, up_to='b5')
        assert len(list(tx_storage.get_all_transactions())) == 8  # 3 genesis + 5 blocks

        artifacts.propagate_with(self.manager, up_to='b10')
        assert len(list(tx_storage.get_all_transactions())) == 13  # 3 genesis + 10 blocks

        artifacts.propagate_with(self.manager, up_to='tx1')
        assert len(list(tx_storage.get_all_transactions())) == 15  # 3 genesis + 10 blocks + dummy + tx1

        artifacts.propagate_with(self.manager)
        assert len(list(tx_storage.get_all_transactions())) == 16  # 3 genesis + 10 blocks + dummy + tx1 + tx2

    def test_nc_transactions(self) -> None:
        blueprint_id = b'x' * 32
        self.nc_catalog.blueprints[blueprint_id] = MyBlueprint

        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis a[0..40]
            a30 < dummy

            tx1.nc_id = "{blueprint_id.hex()}"
            tx1.nc_method = initialize(0)

            tx2.nc_id = tx1
            tx2.nc_method = add(5)
            tx2.nc_deposit = 10 HTR
            tx2.nc_deposit = 5 TKA

            tx3.nc_id = tx1
            tx3.nc_method = sub(3)
            tx3.nc_deposit = 3 HTR
            tx3.nc_withdrawal = 2 TKA

            a31 --> tx1
            a32 --> tx2
            a33 --> tx3
        """)

        for node, vertex in artifacts.list:
            self.manager.on_new_tx(vertex, fails_silently=False)

        tx1 = artifacts.by_name['tx1'].vertex
        self.assertIsInstance(tx1, NanoContract)

        htr_id = TokenUid(b'\0')
        tka_id = TokenUid(artifacts.by_name['TKA'].vertex.hash)

        tx2 = artifacts.by_name['tx2'].vertex
        tx3 = artifacts.by_name['tx3'].vertex

        ctx2 = tx2.get_context()
        self.assertEqual(ctx2.actions, {
            tka_id: NCAction(NCActionType.DEPOSIT, tka_id, 5),
            htr_id: NCAction(NCActionType.DEPOSIT, htr_id, 10),
        })

        ctx3 = tx3.get_context()
        self.assertEqual(ctx3.actions, {
            htr_id: NCAction(NCActionType.DEPOSIT, htr_id, 3),
            tka_id: NCAction(NCActionType.WITHDRAWAL, tka_id, 2),
        })
