import pytest

from hathor.conf.settings import HATHOR_TOKEN_UID
from hathor.nanocontracts import Blueprint, Context, OnChainBlueprint, public
from hathor.nanocontracts.types import NCDepositAction, NCWithdrawalAction, TokenUid
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb
from hathor.transaction import Block, Transaction
from hathor.transaction.headers import FeeHeader, NanoHeader
from hathor.transaction.headers.fee_header import FeeEntry
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenVersion
from tests import unittest
from tests.dag_builder.builder import TestDAGBuilder
from tests.nanocontracts import test_blueprints


class MyBlueprint(Blueprint):
    counter: int

    @public(allow_deposit=True)
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
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

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

        artifacts.propagate_with(self.manager)

        tx1 = artifacts.by_name['tx1'].vertex
        self.assertIsInstance(tx1, Transaction)
        self.assertTrue(tx1.is_nano_contract())

        htr_id = TokenUid(b'\0')
        tka_id = TokenUid(artifacts.by_name['TKA'].vertex.hash)

        tx2 = artifacts.by_name['tx2'].vertex
        tx3 = artifacts.by_name['tx3'].vertex

        ctx2 = tx2.get_nano_header().get_context()
        self.assertEqual(dict(ctx2.actions), {
            tka_id: (NCDepositAction(token_uid=tka_id, amount=5),),
            htr_id: (NCDepositAction(token_uid=htr_id, amount=10),),
        })

        ctx3 = tx3.get_nano_header().get_context()
        self.assertEqual(dict(ctx3.actions), {
            htr_id: (NCDepositAction(token_uid=htr_id, amount=3),),
            tka_id: (NCWithdrawalAction(token_uid=tka_id, amount=2),),
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
        bet_code = load_builtin_blueprint_for_ocb('bet.py', 'Bet', test_blueprints)
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
        nc1, nc2, nc3 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3'], Transaction)

        assert nc1.is_nano_contract()
        assert nc2.is_nano_contract()
        assert nc3.is_nano_contract()

        assert ocb1.get_blueprint_class().__name__ == 'Bet'
        assert nc1.get_nano_header().nc_id == ocb1.hash
        blueprint_class = self.manager.tx_storage.get_blueprint_class(ocb1.hash)
        assert blueprint_class.__name__ == 'Bet'

        assert ocb2.get_blueprint_class().__name__ == 'TestBlueprint1'
        assert nc2.get_nano_header().nc_id == ocb2.hash
        blueprint_class = self.manager.tx_storage.get_blueprint_class(ocb2.hash)
        assert blueprint_class.__name__ == 'TestBlueprint1'

        assert ocb3.get_blueprint_class().__name__ == 'MyBlueprint'
        assert nc3.get_nano_header().nc_id == ocb3.hash
        blueprint_class = self.manager.tx_storage.get_blueprint_class(ocb3.hash)
        assert blueprint_class.__name__ == 'MyBlueprint'

    def test_fee_based_token(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..10]
            b10 < dummy

            FBT1.token_version = fee
            FBT1.fee = 1 HTR

            FBT2.token_version = fee
            FBT2.fee = 1 HTR

            tx1.out[0] = 111 FBT1
            tx1.out[1] = 222 FBT2
            tx1.fee = 1 HTR
            tx1.fee = 100 DBT
            tx1.fee_token = FBT1
            tx1.fee_token = FBT2
        ''')
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        dbt, fbt1, fbt2 = artifacts.get_typed_vertices(('DBT', 'FBT1', 'FBT2'), TokenCreationTransaction)

        assert dbt.token_version is TokenVersion.DEPOSIT
        assert fbt1.token_version is TokenVersion.FEE
        assert fbt2.token_version is TokenVersion.FEE

        assert len(tx1.headers) == 1
        fee_header = tx1.headers[0]

        assert isinstance(fee_header, FeeHeader)
        assert fee_header.tx == tx1
        assert fee_header.get_fees() == [
            FeeEntry(token_uid=HATHOR_TOKEN_UID, amount=1),
            FeeEntry(token_uid=dbt.hash, amount=100),
        ]

        assert len(fbt1.headers) == 1
        fee_header = fbt1.headers[0]

        assert isinstance(fee_header, FeeHeader)
        assert fee_header.tx == fbt1
        assert fee_header.get_fees() == [FeeEntry(token_uid=HATHOR_TOKEN_UID, amount=1)]

        assert len(fbt2.headers) == 1
        fee_header = fbt2.headers[0]

        assert isinstance(fee_header, FeeHeader)
        assert fee_header.tx == fbt2
        assert fee_header.get_fees() == [FeeEntry(token_uid=HATHOR_TOKEN_UID, amount=1)]

        artifacts.propagate_with(self.manager)

        assert tx1.get_metadata().validation.is_valid()
        assert dbt.get_metadata().validation.is_valid()
        assert fbt1.get_metadata().validation.is_valid()
        assert fbt2.get_metadata().validation.is_valid()

        assert tx1.get_metadata().voided_by is None
        assert dbt.get_metadata().voided_by is None
        assert fbt1.get_metadata().voided_by is None
        assert fbt2.get_metadata().voided_by is None

    def test_fee_and_nano_headers(self) -> None:
        blueprint_id = b'x' * 32
        self.nc_catalog.blueprints[blueprint_id] = MyBlueprint
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            FBT.token_version = fee
            FBT.fee = 1 HTR

            tx1.out[0] = 123 FBT
            tx1.fee = 1 HTR
            tx1.fee_token = FBT
            tx1.nc_id = "{blueprint_id.hex()}"
            tx1.nc_method = initialize(0)
            tx1.nc_deposit = 100 HTR

            tx1 <-- b11
        ''')

        artifacts.propagate_with(self.manager)
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)

        assert tx1.get_metadata().validation.is_valid()
        assert tx1.get_metadata().nc_execution is NCExecutionState.SUCCESS
        assert tx1.get_metadata().voided_by is None

        assert len(tx1.headers) == 2
        nano_header, fee_header = tx1.headers

        assert isinstance(nano_header, NanoHeader)
        assert isinstance(fee_header, FeeHeader)
