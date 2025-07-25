from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.nc_types import TupleNCType, VarInt32NCType
from hathor.transaction import Block, Transaction
from tests import unittest
from tests.dag_builder.builder import TestDAGBuilder

INT_VARTUPLE_NC_TYPE = TupleNCType(VarInt32NCType())


class BlueprintWithCompoundField(Blueprint):
    dc: dict[str, list[int]]

    @public
    def initialize(self, ctx: Context) -> None:
        assert self.dc.get('foo', []) == []
        self.dc['foo'] = [1, 2, 3]
        self.dc['bar'] = [4, 5, 6, 7]
        assert self.dc['foo'] == [1, 2, 3]
        assert self.dc['bar'] == [4, 5, 6, 7]
        del self.dc['foo']
        try:
            self.dc['foo']
        except KeyError as e:
            assert e.args[0] == b'dc:\x03foo'
        assert 'foo' not in self.dc
        assert 'bar' in self.dc


class TestDictField(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.bp_dict = b'1' * 32
        self.manager.tx_storage.nc_catalog = NCBlueprintCatalog({
            self.bp_dict: BlueprintWithCompoundField,
        })

    def test_dict_field(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc1.nc_id = "{self.bp_dict.hex()}"
            nc1.nc_method = initialize()

            nc1 <-- b11
            nc1 <-- b12
        ''')
        artifacts.propagate_with(self.manager)

        b11, b12 = artifacts.get_typed_vertices(['b11', 'b12'], Block)
        nc1, = artifacts.get_typed_vertices(['nc1'], Transaction)

        assert b11.get_metadata().voided_by is None
        assert nc1.get_metadata().voided_by is None
        assert nc1.get_metadata().first_block == b11.hash

        b11_storage = self.manager.get_nc_storage(b11, nc1.hash)

        with self.assertRaises(KeyError):
            b11_storage.get_obj(b'dc:\x03foo', INT_VARTUPLE_NC_TYPE)
        assert b11_storage.get_obj(b'dc:\x03bar', INT_VARTUPLE_NC_TYPE) == (4, 5, 6, 7)

        assert b12.get_metadata().voided_by is None
        b12_storage = self.manager.get_nc_storage(b12, nc1.hash)

        with self.assertRaises(KeyError):
            b12_storage.get_obj(b'dc:\x03foo', INT_VARTUPLE_NC_TYPE)
        assert b12_storage.get_obj(b'dc:\x03bar', INT_VARTUPLE_NC_TYPE) == (4, 5, 6, 7)
