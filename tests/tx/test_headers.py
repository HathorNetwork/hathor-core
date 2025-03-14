import pytest

from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.nanocontract import DeprecatedNanoContract
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.exceptions import HeaderNotSupported
from hathor.transaction.headers import NanoHeader
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from tests import unittest


class MyTestBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context) -> None:
        pass


class VertexHeadersTest(unittest.TestCase):
    def has_nano_header(self, vertex: BaseTransaction) -> bool:
        for header in vertex.headers:
            if isinstance(header, NanoHeader):
                return True
        return False

    def test_allowed_vertices(self) -> None:
        blueprint_id = b'x' * 32

        manager = self.create_peer('testnet')
        manager.tx_storage.nc_catalog.blueprints[blueprint_id] = MyTestBlueprint

        dag_builder = self.get_dag_builder(manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc1.nc_id = "{blueprint_id.hex()}"
            nc1.nc_method = initialize()

            nc2.type = NanoContract
            nc2.nc_id = "{blueprint_id.hex()}"
            nc2.nc_method = initialize()

            tx1.out[0] = 5 TKA
            tx2.out[0] = 3 TKB

            b12.nc_id = nc1
            b12.nc_method = nop()

            tx2.nc_id = nc1
            tx2.nc_method = nop()

            TKB.nc_id = nc1
            TKB.nc_method = nop()

            dummy < b11 < nc1 < nc2 < TKA < tx1 < b12 < TKB < tx2
        ''')

        artifacts.propagate_with(manager, up_to='dummy')

        vertex: BaseTransaction

        expected_to_pass: list[tuple[str, type[BaseTransaction], bool]] = [
            ('b11', Block, False),
            ('nc1', Transaction, True),
            ('nc2', DeprecatedNanoContract, True),
            ('TKA', TokenCreationTransaction, False),
            ('TKB', TokenCreationTransaction, True),
            ('tx1', Transaction, False),
        ]
        for name, _type, should_have_nano_header in expected_to_pass:
            vertex = artifacts.get_typed_vertex(name, _type)
            assert self.has_nano_header(vertex) == should_have_nano_header
            clone = _type.create_from_struct(bytes(vertex))
            assert bytes(clone) == bytes(vertex)
            assert manager.on_new_tx(vertex, fails_silently=False)

        expected_to_fail: list[tuple[str, type[BaseTransaction], bool]] = [
            ('b12', Block, True),
        ]
        for name, _type, should_have_nano_header in expected_to_fail:
            vertex = artifacts.get_typed_vertex(name, _type)
            assert self.has_nano_header(vertex) == should_have_nano_header
            clone = _type.create_from_struct(bytes(vertex))
            assert bytes(clone) == bytes(vertex)
            with pytest.raises(InvalidNewTransaction) as e:
                manager.on_new_tx(vertex, fails_silently=False)
            assert isinstance(e.value.__cause__, HeaderNotSupported)
