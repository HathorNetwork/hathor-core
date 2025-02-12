import pytest

from hathor.nanocontracts import Blueprint, Context, NanoContract, OnChainBlueprint, public
from hathor.nanocontracts.types import NCAction, NCActionType, TokenUid
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb
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


class DAGCreatorTestCase(unittest.TestCase):
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

        tx1 = artifacts.by_name['tx1'].vertex
        b1 = artifacts.by_name['b1'].vertex
        b40 = artifacts.by_name['b40'].vertex

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

        tx1 = artifacts.by_name['tx1'].vertex
        tka = artifacts.by_name['TKA'].vertex
        c1 = artifacts.by_name['c1'].vertex
        b38 = artifacts.by_name['b38'].vertex

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

        tx1 = artifacts.by_name['tx1'].vertex
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

        b0 = artifacts.by_name['b30'].vertex
        b1 = artifacts.by_name['b31'].vertex
        b2 = artifacts.by_name['b32'].vertex
        b3 = artifacts.by_name['b33'].vertex
        b4 = artifacts.by_name['b34'].vertex
        b5 = artifacts.by_name['b35'].vertex
        b6 = artifacts.by_name['b36'].vertex
        b7 = artifacts.by_name['b37'].vertex

        tx1 = artifacts.by_name['tx1'].vertex
        tx2 = artifacts.by_name['tx2'].vertex
        tx3 = artifacts.by_name['tx3'].vertex
        tx4 = artifacts.by_name['tx4'].vertex

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

        tka = artifacts.by_name['TKA'].vertex
        tx1 = artifacts.by_name['tx1'].vertex

        # TKA token creation transaction
        self.assertIsInstance(tka, TokenCreationTransaction)
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

        for node, vertex in artifacts.list:
            print()
            print(node.name)
            print()
            self.manager.on_new_tx(vertex, fails_silently=False)

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

        artifacts.propagate_with(self.manager)

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

    def test_multiline_literals(self) -> None:
        artifacts = self.dag_builder.build_from_str("""
            tx.attr1 = ```
                test
            ```
            tx.attr2 = ```
                if foo:
                    bar
            ```
        """)
        node = artifacts.by_name['tx'].node

        # asserting with raw shifted strings to make sure we get the expected output.
        assert node.get_required_literal('attr1') == """\
test"""
        assert node.get_required_literal('attr2') == """\
if foo:
    bar"""

        invalid_start_texts = [
            """
                tx.attr1 = a```
                ```
            """,
            """
                tx.attr1 = ```a
                ```
            """,
            """
                tx.attr1 = ```a```
            """,
        ]

        for text in invalid_start_texts:
            with pytest.raises(SyntaxError) as e:
                self.dag_builder.build_from_str(text)
            assert str(e.value) == 'invalid multiline string start'

        invalid_end_texts = [
            """
                tx.attr1 = ```
                a```
            """,
            """
                tx.attr1 = ```
                ```a
            """,
        ]

        for text in invalid_end_texts:
            with pytest.raises(SyntaxError) as e:
                self.dag_builder.build_from_str(text)
            assert str(e.value) == 'invalid multiline string end'

        with pytest.raises(SyntaxError) as e:
            self.dag_builder.build_from_str("""
                tx.attr1 = ```
                    test
            """)
        assert str(e.value) == 'unclosed multiline string'

    def test_on_chain_blueprints(self) -> None:
        bet_code = load_builtin_blueprint_for_ocb('bet.py', 'Bet')
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..11]
            b10 < dummy

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"

            ocb2.ocb_private_key = "{private_key}"
            ocb2.ocb_password = "{password}"

            ocb3.ocb_private_key = "{private_key}"
            ocb3.ocb_password = "{password}"

            nc1.nc_id = ocb1
            nc1.nc_method = initialize("00", "00", 0)

            nc2.nc_id = ocb2
            nc2.nc_method = initialize(0)

            nc3.nc_id = ocb3
            nc3.nc_method = initialize()

            ocb1 <-- ocb2 <-- ocb3 <-- b11
            b11 < nc1 < nc2 < nc3

            ocb1.ocb_code = "{bet_code.encode().hex()}"
            ocb2.ocb_code = test_blueprint1.py, TestBlueprint1
            ocb3.ocb_code = ```
                from hathor.nanocontracts import Blueprint
                from hathor.nanocontracts.context import Context
                from hathor.nanocontracts.types import public
                class MyBlueprint(Blueprint):
                    @public
                    def initialize(self, ctx: Context) -> None:
                        pass
                __blueprint__ = MyBlueprint
            ```
        """)

        artifacts.propagate_with(self.manager)
        ocb1, ocb2, ocb3 = artifacts.get_typed_vertices(['ocb1', 'ocb2', 'ocb3'], OnChainBlueprint)
        nc1, nc2, nc3 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3'], NanoContract)

        assert ocb1.get_blueprint_class().__name__ == 'Bet'
        assert nc1.get_blueprint_class().__name__ == 'Bet'
        assert nc1.get_blueprint_id() == ocb1.hash

        assert ocb2.get_blueprint_class().__name__ == 'TestBlueprint1'
        assert nc2.get_blueprint_class().__name__ == 'TestBlueprint1'
        assert nc2.get_blueprint_id() == ocb2.hash

        assert ocb3.get_blueprint_class().__name__ == 'MyBlueprint'
        assert nc3.get_blueprint_class().__name__ == 'MyBlueprint'
        assert nc3.get_blueprint_id() == ocb3.hash
