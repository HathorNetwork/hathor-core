from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts import Blueprint, Context, public
from hathor.transaction import Transaction
from hathor.transaction.exceptions import TimestampError
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

        self.artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..30]
            b10 < dummy

            tx1.out[0] = 1 HTR
        ''')
        self.artifacts.propagate_with(self.manager, up_to='dummy')

    def test_vertex_too_old(self) -> None:
        tx1 = self.artifacts.get_typed_vertex('tx1', Transaction)
        tx1.timestamp = int(self.manager.reactor.seconds()) - MAX_PAST_TIMESTAMP_ALLOWED
        self.dag_builder._exporter._vertex_resolver(tx1)

        with self.assertRaises(InvalidNewTransaction) as e:
            self.manager.vertex_handler.on_new_mempool_transaction(tx1)
        assert isinstance(e.exception.__cause__, TimestampError)

        tx1 = self.artifacts.get_typed_vertex('tx1', Transaction)
        tx1.timestamp = int(self.manager.reactor.seconds()) - MAX_PAST_TIMESTAMP_ALLOWED + 1
        self.dag_builder._exporter._vertex_resolver(tx1)

        self.manager.vertex_handler.on_new_mempool_transaction(tx1)
