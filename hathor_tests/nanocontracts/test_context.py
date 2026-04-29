from typing import NamedTuple

from hathor.nanocontracts import Blueprint, public
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.nc_types import make_nc_type_for_field_type
from hathor.transaction import Block, Transaction
from hathor.transaction.base_transaction import TxVersion
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.scripts import parse_address_script
from hathor.util import not_none
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.test_blueprint import BYTES_NC_TYPE
from hathorlib.nanocontracts.fields.deque_container import _INDEX_NC_TYPE, _METADATA_NC_TYPE as DQ_METADATA_NC_TYPE


class TxInputDataTuple(NamedTuple):
    tx_id: bytes
    index_: int
    data: bytes


class ScriptInfoTuple(NamedTuple):
    type: str
    address: str
    timelock: int | None


class TxOutputDataTuple(NamedTuple):
    value: int
    raw_script: bytes
    parsed_script: ScriptInfoTuple | None
    token_data: int


class NanoHeaderDataTuple(NamedTuple):
    nc_id: bytes
    nc_method: str
    nc_args_bytes: bytes


class VertexDataTuple(NamedTuple):
    version: int
    hash: bytes
    nonce: int
    signal_bits: int
    work: int


class BlockDataTuple(NamedTuple):
    hash: bytes
    timestamp: int
    height: int


class RememberVertexDataBlueprint(Blueprint):
    vertex_data: VertexDataTuple | None
    block_data: BlockDataTuple | None
    vertex_tokens: list[bytes]
    vertex_parents: list[bytes]
    vertex_inputs: list[TxInputDataTuple]
    vertex_outputs: list[TxOutputDataTuple]
    nano_header: NanoHeaderDataTuple | None

    @public
    def initialize(self, ctx: Context) -> None:
        self.vertex_data = None
        self.block_data = None
        self.vertex_tokens = []
        self.vertex_parents = []
        self.vertex_inputs = []
        self.vertex_outputs = []
        self.nano_header = None

    @public
    def remember_context(self, ctx: Context) -> None:
        self.vertex_data = VertexDataTuple(
            version=ctx.vertex.version,
            hash=ctx.vertex.hash,
            nonce=ctx.vertex.nonce,
            signal_bits=ctx.vertex.signal_bits,
            work=ctx.vertex.work,
        )
        self.block_data = BlockDataTuple(
            hash=ctx.block.hash,
            timestamp=ctx.block.timestamp,
            height=ctx.block.height
        )
        self.vertex_tokens.extend(ctx.vertex.tokens)
        self.vertex_parents.extend(ctx.vertex.parents)

        for tx_input in ctx.vertex.inputs:
            self.vertex_inputs.append(
                TxInputDataTuple(
                    tx_id=tx_input.tx_id,
                    index_=tx_input.index,
                    data=tx_input.data,
                )
            )

        for tx_out in ctx.vertex.outputs:
            assert tx_out.parsed_script is not None
            self.vertex_outputs.append(
                TxOutputDataTuple(
                    value=tx_out.value,
                    raw_script=tx_out.raw_script,
                    parsed_script=ScriptInfoTuple(
                        type=tx_out.parsed_script.type,
                        address=tx_out.parsed_script.address,
                        timelock=tx_out.parsed_script.timelock,
                    ),
                    token_data=tx_out.token_data,
                )
            )

        assert len(ctx.vertex.headers) == 1
        nano_header = ctx.vertex.headers[0]
        self.nano_header = NanoHeaderDataTuple(
            nc_id=nano_header.nc_id,  # type: ignore[attr-defined]
            nc_method=nano_header.nc_method,  # type: ignore[attr-defined]
            nc_args_bytes=nano_header.nc_args_bytes  # type: ignore[attr-defined]
        )


class ContextTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self.gen_random_contract_id()
        self.manager.blueprint_service.register_blueprint(self.blueprint_id, RememberVertexDataBlueprint)
        self.address = self.gen_random_address()

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
        b12, = artifacts.get_typed_vertices(['b12'], Block)
        nc1, nc2 = artifacts.get_typed_vertices(['nc1', 'nc2'], Transaction)

        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc2.get_metadata().nc_execution == NCExecutionState.SUCCESS

        # this is the vertex data that was observed by nc2 when remember_context was called
        nc_storage = self.manager.get_nc_storage(b12, nc1.hash)

        vertex_data_nc_type = make_nc_type_for_field_type(VertexDataTuple | None)  # type: ignore[arg-type]
        block_data_nc_type = make_nc_type_for_field_type(BlockDataTuple | None)  # type: ignore[arg-type]
        vertex_data = nc_storage.get_obj(b'vertex_data', vertex_data_nc_type)
        block_data = nc_storage.get_obj(b'block_data', block_data_nc_type)
        vertex_tokens = nc_storage.get_obj(b'vertex_tokens:__metadata__', DQ_METADATA_NC_TYPE)

        self.assertEqual(vertex_data.version, TxVersion.REGULAR_TRANSACTION)
        self.assertEqual(vertex_data.hash, nc2.hash)
        self.assertEqual(vertex_data.signal_bits, 0)
        self.assertEqual(vertex_data.work, 2)
        self.assertEqual(vertex_tokens.length, 0)
        self.assertEqual(block_data.hash, b12.hash)
        self.assertEqual(block_data.timestamp, b12.timestamp)
        self.assertEqual(block_data.height, b12.get_height())
        self.assertEqual(vertex_data.nonce, nc2.nonce)

        for i, parent_tx in enumerate(nc2.parents):
            storage_parent = nc_storage.get_obj(
                b':'.join([b'vertex_parents', _INDEX_NC_TYPE.to_bytes(i)]),
                BYTES_NC_TYPE
            )
            assert storage_parent == parent_tx

        input_nc_type = make_nc_type_for_field_type(TxInputDataTuple)
        for i, input_tx in enumerate(nc2.inputs):
            storage_input = nc_storage.get_obj(
                b':'.join([b'vertex_inputs', _INDEX_NC_TYPE.to_bytes(i)]),
                input_nc_type,
            )
            assert storage_input.tx_id == input_tx.tx_id
            assert storage_input.index_ == input_tx.index
            assert storage_input.data == input_tx.data

        output_nc_type = make_nc_type_for_field_type(TxOutputDataTuple)
        for i, output in enumerate(nc2.outputs):
            storage_out = nc_storage.get_obj(
                b':'.join([b'vertex_outputs', _INDEX_NC_TYPE.to_bytes(i)]),
                output_nc_type,
            )
            parsed = not_none(parse_address_script(output.script))
            assert storage_out.value == output.value
            assert storage_out.raw_script == output.script
            assert not_none(storage_out.parsed_script).type == parsed.get_type()
            assert not_none(storage_out.parsed_script).address == parsed.get_address()
            assert not_none(storage_out.parsed_script).timelock == parsed.get_timelock()
            assert storage_out.token_data == output.token_data

        nano_header_data = nc_storage.get_obj(
            b'nano_header',
            make_nc_type_for_field_type(NanoHeaderDataTuple | None),  # type: ignore[arg-type]
        )
        self.assertEqual(nano_header_data.nc_id, nc1.hash)
        self.assertEqual(nano_header_data.nc_method, 'remember_context')
        self.assertEqual(nano_header_data.nc_args_bytes, b'\x00')
