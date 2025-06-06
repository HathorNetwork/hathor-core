from hathor.checkpoint import Checkpoint
from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts import Blueprint, Context, public
from hathor.transaction import Block, Transaction
from hathor.transaction.exceptions import (
    ConflictWithConfirmedTxError,
    InvalidToken,
    TimestampError,
    TooManyTokens,
    UnusedTokensError,
)
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.verification.vertex_verifier import MAX_PAST_TIMESTAMP_ALLOWED
from tests import unittest
from tests.dag_builder.builder import TestDAGBuilder


class MyTestBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context) -> None:
        pass


class VertexHeadersTest(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = b'x' * 32
        self.manager = self.create_peer('unittests')
        self.manager.tx_storage.nc_catalog.blueprints[self.blueprint_id] = MyTestBlueprint
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_vertex_too_old(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..30]
            b10 < dummy

            tx1.out[0] = 1 HTR
        ''')
        artifacts.propagate_with(self.manager, up_to='dummy')
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        tx1.timestamp = int(self.manager.reactor.seconds()) - MAX_PAST_TIMESTAMP_ALLOWED
        self.dag_builder._exporter._vertex_resolver(tx1)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx1)
        assert isinstance(e.exception.__cause__, TimestampError)

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        tx1.timestamp = int(self.manager.reactor.seconds()) - MAX_PAST_TIMESTAMP_ALLOWED + 1
        self.dag_builder._exporter._vertex_resolver(tx1)

        self.manager.vertex_handler.on_new_mempool_transaction(tx1)

    def test_tokens(self) -> None:
        tx1_description = '\n'.join([
            f'tx1.out[{i}] = 1 TK_{i}' for i in range(15)
        ])
        tx2_description = '\n'.join([
            f'tx2.out[{i}] = 1 TK_{i}' for i in range(17)
        ])
        tx3_description = '\n'.join([
            f'tx3.out[{i}] = 1 TK_{i}' for i in range(9)
        ])
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..30]
            b10 < dummy

            {tx1_description}
            {tx2_description}
            {tx3_description}

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 TK_15

            tx3.nc_id = "{self.blueprint_id.hex()}"
            tx3.nc_method = initialize()
            tx3.nc_deposit = 1 TK_9

            b30 < tx1 < tx2 < tx3
        ''')
        artifacts.propagate_with(self.manager, up_to_before='tx2')
        tx1, tx2, tx3 = artifacts.get_typed_vertices(['tx1', 'tx2', 'tx3'], Transaction)
        tk_9, tk_15 = artifacts.get_typed_vertices(['TK_9', 'TK_15'], TokenCreationTransaction)

        assert len(tx1.tokens) == 16
        # assert tk_15.hash not in tx1.tokens
        assert tx1.get_metadata().voided_by is None

        # need to fix the timestamp to pass the old vertices mempool verification
        tx2.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx2)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx2)
        assert isinstance(e.exception.__cause__, TooManyTokens)

        tx3_original_tokens = list(tx3.tokens)

        # add one duplicate token
        tx3.tokens.append(tx3.tokens[0])
        tx3.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx3)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx3)
        assert isinstance(e.exception.__cause__, InvalidToken)
        tx3.tokens = list(tx3_original_tokens)

        # add one unused token
        tx3.tokens.append(tk_15.hash)
        tx3.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx3)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx3)
        assert isinstance(e.exception.__cause__, UnusedTokensError)

    def test_conflict_with_confirmed_tx(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..30]
            b10 < dummy

            tx1.out[0] <<< tx2 tx3
            tx2 <-- b30

            tx2 < b30 < tx3
        ''')
        artifacts.propagate_with(self.manager, up_to_before='tx3')
        b30 = artifacts.get_typed_vertex('b30', Block)
        tx2, tx3 = artifacts.get_typed_vertices(['tx2', 'tx3'], Transaction)

        assert tx2.get_metadata().voided_by is None
        assert tx2.get_metadata().first_block == b30.hash
        assert b30.get_metadata().voided_by is None

        # need to fix the timestamp to pass the old vertices mempool verification
        tx3.timestamp = int(self.manager.reactor.seconds())
        self.dag_builder._exporter._vertex_resolver(tx3)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx3)
        assert isinstance(e.exception.__cause__, ConflictWithConfirmedTxError)

    def test_checkpoints(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..30]
            blockchain b4 c[5..5]

            b30 < c5
        ''')

        checkpoints = []
        for height in [1, 5, 10, 15, 20]:
            blk = artifacts.get_typed_vertex(f'b{height}', Block)
            checkpoints.append(Checkpoint(height=height, hash=blk.hash))

        new_settings = self._settings._replace(CHECKPOINTS=checkpoints)
        manager2 = self.create_peer('unittests', settings=new_settings)
        print([(cp.height, cp.hash) for cp in manager2.checkpoints])
        print([(cp.height, cp.hash) for cp in checkpoints])
        assert [(cp.height, cp.hash) for cp in manager2.checkpoints] == [(cp.height, cp.hash) for cp in checkpoints]
        artifacts.propagate_with(manager2, up_to='b30')

        c5 = artifacts.get_typed_vertex('c5', Block)
        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_block(c5, deps=[])
        assert isinstance(e.exception.__cause__, CheckpointError)
