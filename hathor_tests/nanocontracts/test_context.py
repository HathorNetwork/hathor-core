import copy

from hathor.nanocontracts import Blueprint, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.vertex_data import BlockData, NanoHeaderData, VertexData
from hathor.transaction import Block, Transaction
from hathor.transaction.base_transaction import TxVersion
from hathor.transaction.scripts import parse_address_script
from hathor.util import not_none
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase

GLOBAL_CTX_DATA: tuple[VertexData, BlockData] | None = None


class RememberVertexDataBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def remember_context(self, ctx: Context) -> None:
        global GLOBAL_CTX_DATA
        GLOBAL_CTX_DATA = copy.deepcopy((ctx.vertex, ctx.block))


class ContextTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        global GLOBAL_CTX_DATA

        super().setUp()

        self.blueprint_id = self.gen_random_contract_id()
        self.manager.tx_storage.nc_catalog = NCBlueprintCatalog({
            self.blueprint_id: RememberVertexDataBlueprint,
        })
        self.address = self.gen_random_address()

        # clear vertex-data before and after
        GLOBAL_CTX_DATA = None

    def tearDown(self) -> None:
        global GLOBAL_CTX_DATA

        super().tearDown()
        # clear vertex-data before and after
        GLOBAL_CTX_DATA = None

    def test_vertex_data(self) -> None:
        global GLOBAL_CTX_DATA

        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy
            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize()
            nc1 <-- b11
            nc2.nc_id = nc1
            nc2.nc_method = remember_context()
            nc1 <-- nc2 <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        b12, = artifacts.get_typed_vertices(['b12'], Block)
        nc1, nc2 = artifacts.get_typed_vertices(['nc1', 'nc2'], Transaction)

        # this is the vertex data that was observed by nc2 when remember_context was called
        assert GLOBAL_CTX_DATA is not None
        vertex_data, block_data = copy.deepcopy(GLOBAL_CTX_DATA)

        self.assertEqual(vertex_data.version, TxVersion.REGULAR_TRANSACTION)
        self.assertEqual(vertex_data.hash, nc2.hash)
        self.assertEqual(vertex_data.signal_bits, 0)
        self.assertEqual(vertex_data.weight, 1.0)
        self.assertEqual(vertex_data.tokens, ())
        self.assertEqual(block_data.hash, b12.hash)
        self.assertEqual(block_data.timestamp, b12.timestamp)
        self.assertEqual(block_data.height, b12.get_height())
        self.assertEqual(vertex_data.nonce, nc2.nonce)
        self.assertEqual(vertex_data.parents, tuple(nc2.parents))

        for i, input_tx in enumerate(nc2.inputs):
            assert vertex_data.inputs[i].tx_id == input_tx.tx_id
            assert vertex_data.inputs[i].index == input_tx.index
            assert vertex_data.inputs[i].data == input_tx.data

        for i, output in enumerate(nc2.outputs):
            parsed = not_none(parse_address_script(output.script))
            assert vertex_data.outputs[i].value == output.value
            assert vertex_data.outputs[i].raw_script == output.script
            assert not_none(vertex_data.outputs[i].parsed_script).type == parsed.get_type()
            assert not_none(vertex_data.outputs[i].parsed_script).address == parsed.get_address()
            assert not_none(vertex_data.outputs[i].parsed_script).timelock == parsed.get_timelock()
            assert vertex_data.outputs[i].token_data == output.token_data

        self.assertEqual(set(vertex_data.parents), set(nc2.parents))
        nano_header_data, = vertex_data.headers
        assert isinstance(nano_header_data, NanoHeaderData)
        self.assertEqual(nano_header_data.nc_id, nc1.hash)
        self.assertEqual(nano_header_data.nc_method, 'remember_context')
        self.assertEqual(nano_header_data.nc_args_bytes, b'\x00')
