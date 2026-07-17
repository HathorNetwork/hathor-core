# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor import Blueprint, Context, public
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathorlib.nanocontracts import fields as nc_fields
from hathorlib.nanocontracts.nc_types import make_nc_type_for_arg_type
from hathorlib.nanocontracts.types import Amount
from hathorlib.serialization import Serializer
from hathorlib.serialization.encoding.output_value import encode_length_prefix_varint
from hathorlib.token_amount_version import TokenAmountVersion
from hathorlib.utils.leb128 import encode_signed as encode_signed_leb128, encode_unsigned as encode_unsigned_leb128


class MyBlueprint(Blueprint):
    x: int
    y: Amount

    @public
    def initialize(self, ctx: Context) -> None:
        self.x = 64
        self.y = Amount(64)


class TestNano(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id1 = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V1)
        self.blueprint_id2 = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V2)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def _set_force_legacy_fields(self, value: bool) -> None:
        """Set the global `FORCE_LEGACY_FIELDS` flag, restoring the original value at test teardown."""
        original = nc_fields.FORCE_LEGACY_FIELDS
        nc_fields.FORCE_LEGACY_FIELDS = value
        self.addCleanup(setattr, nc_fields, 'FORCE_LEGACY_FIELDS', original)

    def test_legacy_serialization(self) -> None:
        self._set_force_legacy_fields(True)
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            nc1.nc_id = "{self.blueprint_id1.hex()}"
            nc1.nc_method = initialize()
            nc1.token_amount_version = V1

            nc1 <-- b11
        ''')

        artifacts.propagate_with(self.manager)
        b11 = artifacts.get_typed_vertex('b11', Block)
        nc1, = artifacts.get_typed_vertices(('nc1',), Transaction)

        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        storage = self.manager.get_nc_storage(b11, nc1.hash)

        # We use V1 to generate the field types since we're forcing legacy serialization
        x_nc_type = make_nc_type_for_arg_type(int, token_amount_version=TokenAmountVersion.V1)
        y_nc_type = make_nc_type_for_arg_type(Amount, token_amount_version=TokenAmountVersion.V1)

        x = storage.get_obj(b'x', x_nc_type)
        assert type(x) is int
        assert x == 64

        y = storage.get_obj(b'y', y_nc_type)
        assert type(y) is Amount  # deserialized values are wrapped back into the declared class.
        assert y == 64

        x_key = storage._to_attr_key(b'x')
        x_raw = storage._trie.get(bytes(x_key))
        assert x_raw == b'\x01' + encode_signed_leb128(64) == b'\x01\xc0\x00'

        y_key = storage._to_attr_key(b'y')
        y_raw = storage._trie.get(bytes(y_key))
        assert y_raw == b'\x01' + encode_unsigned_leb128(64) == b'\x01\x40'

    def test_new_serialization(self) -> None:
        self._set_force_legacy_fields(False)
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            nc1.nc_id = "{self.blueprint_id1.hex()}"
            nc1.nc_method = initialize()
            nc1.token_amount_version = V1

            nc1 <-- b11
        ''')

        artifacts.propagate_with(self.manager)
        b11 = artifacts.get_typed_vertex('b11', Block)
        nc1, = artifacts.get_typed_vertices(('nc1',), Transaction)

        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        storage = self.manager.get_nc_storage(b11, nc1.hash)

        # We use V2 to generate the field types since we're using the new serialization,
        # even though the contract itself is V1: storage serialization is global.
        x_nc_type = make_nc_type_for_arg_type(int, token_amount_version=TokenAmountVersion.V2)
        y_nc_type = make_nc_type_for_arg_type(Amount, token_amount_version=TokenAmountVersion.V2)

        x = storage.get_obj(b'x', x_nc_type)
        assert type(x) is int
        assert x == 64

        y = storage.get_obj(b'y', y_nc_type)
        assert type(y) is Amount  # deserialized values are wrapped back into the declared class.
        assert y == 64

        x_key = storage._to_attr_key(b'x')
        x_raw = storage._trie.get(bytes(x_key))
        se = Serializer.build_bytes_serializer()
        encode_length_prefix_varint(se, 64, signed=True)
        assert x_raw == b'\x01' + bytes(se.finalize()) == b'\x01\x01\x40'

        y_key = storage._to_attr_key(b'y')
        y_raw = storage._trie.get(bytes(y_key))
        se = Serializer.build_bytes_serializer()
        encode_length_prefix_varint(se, 64, signed=False)
        assert y_raw == b'\x01' + bytes(se.finalize()) == b'\x01\x01\x40'
