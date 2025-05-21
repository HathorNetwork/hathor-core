from hathor.nanocontracts import Blueprint, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.vertex_data import BlockData, NanoHeaderData, VertexData
from hathor.transaction import Block, Transaction
from hathor.transaction.base_transaction import TxVersion
from tests.dag_builder.builder import TestDAGBuilder
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class RememberVertexDataBlueprint(Blueprint):
    # XXX: this signature is incorrect, but the implementation with pickle serialization ignores that
    last_vertex: tuple[dict[str, str]]

    @public
    def initialize(self, ctx: Context) -> None:
        self.last_vertex = ({},)

    @public
    def remember_context(self, ctx: Context) -> None:
        from dataclasses import asdict
        vertex_data = asdict(ctx.vertex)
        self.last_vertex = (vertex_data,)


class ContextTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()

        self.blueprint_id = self.gen_random_nanocontract_id()
        self.manager.tx_storage.nc_catalog = NCBlueprintCatalog({
            self.blueprint_id: RememberVertexDataBlueprint,
        })
        self.address = self.gen_random_address()

    def _reconstruct_vertex_data(self, dict_: dict) -> VertexData:
        block_data = BlockData(**dict_.pop('block'))
        dict_ |= {'inputs': (), 'outputs': (), 'parents': ()}
        nano_header_data, = dict_.pop('headers')
        dict_['headers'] = (NanoHeaderData(**nano_header_data),)
        return VertexData(block=block_data, **dict_)

    def test_vertex_data(self) -> None:
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
        b11, b12 = artifacts.get_typed_vertices(['b11', 'b12'], Block)
        nc1, nc2 = artifacts.get_typed_vertices(['nc1', 'nc2'], Transaction)
        nc_storage = self.manager.get_nc_storage(b12, nc1.hash)

        # this is the vertex data that was observed by nc2 when remember_context was called
        vertex_data_dict, = nc_storage.get('last_vertex')
        vertex_data = self._reconstruct_vertex_data(vertex_data_dict)

        # XXX: nonce varies, even for a weight of 1.0
        # XXX: inptus/outputs/parents ignored since the dag builder will pick whatever to fill it in

        self.assertEqual(vertex_data.version, TxVersion.REGULAR_TRANSACTION)
        self.assertEqual(vertex_data.hash, nc2.hash)
        self.assertEqual(vertex_data.signal_bits, 0)
        self.assertEqual(vertex_data.weight, 1.0)
        self.assertEqual(vertex_data.tokens, ())
        self.assertEqual(vertex_data.block.hash, b12.hash)
        self.assertEqual(vertex_data.block.timestamp, b12.timestamp)
        self.assertEqual(vertex_data.block.height, b12.get_height())
        nano_header_data, = vertex_data.headers
        assert isinstance(nano_header_data, NanoHeaderData)
        self.assertEqual(nano_header_data.nc_version, 1)
        self.assertEqual(nano_header_data.nc_id, nc1.hash)
        self.assertEqual(nano_header_data.nc_method, 'remember_context')
        self.assertEqual(nano_header_data.nc_args_bytes, b'\x00')
