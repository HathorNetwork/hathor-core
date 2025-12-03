from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.fields.container import INIT_NC_TYPE
from hathor.nanocontracts.fields.deque_container import _METADATA_NC_TYPE as METADATA_NC_TYPE
from hathor.nanocontracts.nc_types import VarInt32NCType
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder

INT_NC_TYPE = VarInt32NCType()


class BlueprintWithCompoundField(Blueprint):
    dc: dict[str, list[int]]

    @public
    def initialize(self, ctx: Context) -> None:
        self.dc = {}
        self.dc['foo'] = [1, 2]
        assert len(self.dc) == 1
        foo = self.dc['foo']
        foo.append(3)
        assert len(foo) == 3
        self.dc['bar'] = [4, 5, 6, 7]
        assert len(self.dc) == 2
        assert self.dc['foo'] == [1, 2, 3]
        assert self.dc['bar'] == [4, 5, 6, 7]
        foo = self.dc['foo']
        foo.pop()
        assert len(foo) == 2
        foo.pop()
        assert len(foo) == 1
        foo.pop()
        assert len(foo) == 0
        assert len(self.dc['foo']) == 0
        assert 'bar' in self.dc
        assert len(self.dc) == 2
        del self.dc['foo']
        assert len(self.dc) == 1
        assert 'bar' in self.dc
        assert 'foo' not in self.dc
        # XXX: implicit creation fails:
        try:
            self.dc['foo']
        except KeyError as e:
            assert e.args == ('foo',)
        else:
            assert False
        assert len(self.dc) == 1
        # remove foo, test will check it was removed from the storage
        del self.dc['foo']


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
            b11_storage.get_obj(b'dc:\x03foo:__init__', INIT_NC_TYPE)
        assert b11_storage.get_obj(b'dc:\x03bar:__init__', INIT_NC_TYPE) is True

        assert b12.get_metadata().voided_by is None
        b12_storage = self.manager.get_nc_storage(b12, nc1.hash)

        with self.assertRaises(KeyError):
            b12_storage.get_obj(b'dc:\x03foo:__init__', INIT_NC_TYPE)
        assert b12_storage.get_obj(b'dc:\x03bar:__init__', INIT_NC_TYPE) is True
        assert b12_storage.get_obj(b'dc:\x03bar:\x00', INT_NC_TYPE) == 4
        assert b12_storage.get_obj(b'dc:\x03bar:\x01', INT_NC_TYPE) == 5
        assert b12_storage.get_obj(b'dc:\x03bar:\x02', INT_NC_TYPE) == 6
        assert b12_storage.get_obj(b'dc:\x03bar:\x03', INT_NC_TYPE) == 7
        with self.assertRaises(KeyError):
            b12_storage.get_obj(b'dc:\x03bar:\x04', INT_NC_TYPE)
        metadata = b12_storage.get_obj(b'dc:\x03bar:__metadata__', METADATA_NC_TYPE)
        assert metadata.first_index == 0
        assert metadata.last_index == 3
        assert metadata.length == 4
        assert not metadata.reversed
