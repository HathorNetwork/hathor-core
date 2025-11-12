from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.fields.container import INIT_NC_TYPE, KEY_SEPARATOR
from hathor.nanocontracts.fields.deque_container import _METADATA_NC_TYPE as METADATA_NC_TYPE
from hathor.nanocontracts.nc_types import StrNCType, VarInt32NCType
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder

INT_NC_TYPE = VarInt32NCType()
STR_NC_TYPE = StrNCType()


class DictOfDictBlueprint(Blueprint):
    container: dict[str, dict[int, int]]

    @public
    def initialize(self, ctx: Context) -> None:
        self.container = {}
        self.container['alpha'] = {1: 10, 2: 20}
        inner = self.container.get('beta', {})
        inner[3] = 30
        inner[4] = 40
        del inner[3]


class ListOfDictBlueprint(Blueprint):
    container: list[dict[str, int]]

    @public
    def initialize(self, ctx: Context) -> None:
        self.container = []
        self.container.append({'k1': 111, 'k2': 222})
        self.container.append({})
        d = self.container[1]
        d['z'] = 999


class DictListDictBlueprint(Blueprint):
    container: dict[str, list[dict[int, int]]]

    @public
    def initialize(self, ctx: Context) -> None:
        self.container = {}
        self.container['A'] = []
        self.container['A'].append({1: 10})
        self.container['A'].append({2: 20, 3: 30})
        d0 = self.container['A'][0]
        d0[4] = 40


class DictOfSetBlueprint(Blueprint):
    container: dict[str, set[int]]

    @public
    def initialize(self, ctx: Context) -> None:
        self.container = {}
        self.container['s'] = {1, 2}
        s2 = self.container.get('t', set())
        s2.add(3)


class TestNestedContainers(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.bp1 = b'1' * 32
        self.bp2 = b'2' * 32
        self.bp3 = b'3' * 32
        self.bp4 = b'4' * 32
        self.manager.tx_storage.nc_catalog = NCBlueprintCatalog({
            self.bp1: DictOfDictBlueprint,
            self.bp2: ListOfDictBlueprint,
            self.bp3: DictListDictBlueprint,
            self.bp4: DictOfSetBlueprint,
        })

    def _run_single_call(self, bp_id: bytes) -> tuple[Block, Block, Transaction]:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc1.nc_id = "{bp_id.hex()}"
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

        assert b12.get_metadata().voided_by is None
        return b11, b12, nc1

    def test_dict_of_dict(self) -> None:
        b11, b12, nc1 = self._run_single_call(self.bp1)
        storage = self.manager.get_nc_storage(b12, nc1.hash)

        # Keys for container['alpha'] entries
        alpha = KEY_SEPARATOR.join([b'container', STR_NC_TYPE.to_bytes('alpha')])
        beta = KEY_SEPARATOR.join([b'container', STR_NC_TYPE.to_bytes('beta')])

        # containers are initialized immediately
        assert storage.get_obj(KEY_SEPARATOR.join([alpha, b'__init__']), INIT_NC_TYPE) is True
        assert storage.get_obj(KEY_SEPARATOR.join([beta, b'__init__']), INIT_NC_TYPE) is True

        # alpha={1:10, 2:20}
        assert storage.get_obj(KEY_SEPARATOR.join([alpha, INT_NC_TYPE.to_bytes(1)]), INT_NC_TYPE) == 10
        assert storage.get_obj(KEY_SEPARATOR.join([alpha, INT_NC_TYPE.to_bytes(2)]), INT_NC_TYPE) == 20

        # beta has 4 only (3 was deleted)
        with self.assertRaises(KeyError):
            storage.get_obj(KEY_SEPARATOR.join([beta, INT_NC_TYPE.to_bytes(3)]), INT_NC_TYPE)
        assert storage.get_obj(KEY_SEPARATOR.join([beta, INT_NC_TYPE.to_bytes(4)]), INT_NC_TYPE) == 40

    def test_list_of_dict(self) -> None:
        b11, b12, nc1 = self._run_single_call(self.bp2)
        storage = self.manager.get_nc_storage(b12, nc1.hash)

        # list metadata exists
        assert storage.has_obj(KEY_SEPARATOR.join([b'container', b'__metadata__']))

        # first element dict: {'k1':111, 'k2':222}
        idx0 = KEY_SEPARATOR.join([b'container', INT_NC_TYPE.to_bytes(0)])
        assert storage.get_obj(KEY_SEPARATOR.join([idx0, b'__init__']), INIT_NC_TYPE) is True
        assert storage.get_obj(KEY_SEPARATOR.join([idx0, STR_NC_TYPE.to_bytes('k1')]), INT_NC_TYPE) == 111
        assert storage.get_obj(KEY_SEPARATOR.join([idx0, STR_NC_TYPE.to_bytes('k2')]), INT_NC_TYPE) == 222

        # second element dict: {'z': 999}
        idx1 = KEY_SEPARATOR.join([b'container', INT_NC_TYPE.to_bytes(1)])
        assert storage.get_obj(KEY_SEPARATOR.join([idx1, b'__init__']), INIT_NC_TYPE) is True
        assert storage.get_obj(KEY_SEPARATOR.join([idx1, STR_NC_TYPE.to_bytes('z')]), INT_NC_TYPE) == 999

        # no third element
        idx2 = KEY_SEPARATOR.join([b'container', INT_NC_TYPE.to_bytes(2)])
        with self.assertRaises(KeyError):
            storage.get_obj(idx2, INT_NC_TYPE)

    def test_dict_list_dict(self) -> None:
        b11, b12, nc1 = self._run_single_call(self.bp3)
        storage = self.manager.get_nc_storage(b12, nc1.hash)

        a_prefix = KEY_SEPARATOR.join([b'container', STR_NC_TYPE.to_bytes('A')])

        # outer list container initialized
        assert storage.get_obj(KEY_SEPARATOR.join([a_prefix, b'__init__']), INIT_NC_TYPE) is True

        # list metadata and length
        metadata = storage.get_obj(KEY_SEPARATOR.join([a_prefix, b'__metadata__']), METADATA_NC_TYPE)
        assert metadata.first_index == 0
        assert metadata.last_index == 1
        assert metadata.length == 2
        assert not metadata.reversed

        # first dict element {1:10, 4:40}
        a0 = KEY_SEPARATOR.join([a_prefix, INT_NC_TYPE.to_bytes(0)])
        assert storage.get_obj(KEY_SEPARATOR.join([a0, b'__init__']), INIT_NC_TYPE) is True
        assert storage.get_obj(KEY_SEPARATOR.join([a0, INT_NC_TYPE.to_bytes(1)]), INT_NC_TYPE) == 10
        assert storage.get_obj(KEY_SEPARATOR.join([a0, INT_NC_TYPE.to_bytes(4)]), INT_NC_TYPE) == 40

        # second dict element {2:20, 3:30}
        a1 = KEY_SEPARATOR.join([a_prefix, INT_NC_TYPE.to_bytes(1)])
        assert storage.get_obj(KEY_SEPARATOR.join([a1, b'__init__']), INIT_NC_TYPE) is True
        assert storage.get_obj(KEY_SEPARATOR.join([a1, INT_NC_TYPE.to_bytes(2)]), INT_NC_TYPE) == 20
        assert storage.get_obj(KEY_SEPARATOR.join([a1, INT_NC_TYPE.to_bytes(3)]), INT_NC_TYPE) == 30

    def test_dict_of_set(self) -> None:
        b11, b12, nc1 = self._run_single_call(self.bp4)
        storage = self.manager.get_nc_storage(b12, nc1.hash)

        s_prefix = KEY_SEPARATOR.join([b'container', STR_NC_TYPE.to_bytes('s')])
        t_prefix = KEY_SEPARATOR.join([b'container', STR_NC_TYPE.to_bytes('t')])

        # containers initialized
        assert storage.get_obj(KEY_SEPARATOR.join([s_prefix, b'__init__']), INIT_NC_TYPE) is True
        assert storage.get_obj(KEY_SEPARATOR.join([t_prefix, b'__init__']), INIT_NC_TYPE) is True

        # s contains {1,2}
        assert storage.get_obj(KEY_SEPARATOR.join([s_prefix, INT_NC_TYPE.to_bytes(1)]), INT_NC_TYPE) == 1
        assert storage.get_obj(KEY_SEPARATOR.join([s_prefix, INT_NC_TYPE.to_bytes(2)]), INT_NC_TYPE) == 2

        # t contains {3}
        assert storage.get_obj(KEY_SEPARATOR.join([t_prefix, INT_NC_TYPE.to_bytes(3)]), INT_NC_TYPE) == 3
        with self.assertRaises(KeyError):
            storage.get_obj(KEY_SEPARATOR.join([t_prefix, INT_NC_TYPE.to_bytes(4)]), INT_NC_TYPE)
