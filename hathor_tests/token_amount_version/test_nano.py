#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from hathor import Blueprint, Context, public
from hathor.transaction import Transaction, Block
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathorlib.nanocontracts.nc_types import make_nc_type_for_arg_type
from hathorlib.nanocontracts.types import Amount
from hathorlib.token_amount_version import TokenAmountVersion
from hathorlib.utils.leb128 import encode_signed as encode_signed_leb128, encode_unsigned as encode_unsigned_leb128

X_NC_TYPE = make_nc_type_for_arg_type(int)
Y_NC_TYPE = make_nc_type_for_arg_type(Amount)


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

    def test_current_serialization(self) -> None:
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

        x = storage.get_obj(b'x', X_NC_TYPE)
        assert type(x) is int
        assert x == 64

        y = storage.get_obj(b'y', Y_NC_TYPE)
        assert type(y) is int  # the storage returns an int instead of the Amount wrapper.
        assert y == 64

        x_key = storage._to_attr_key(b'x')
        x_raw = storage._trie.get(bytes(x_key))
        assert x_raw == b'\x01' + encode_signed_leb128(64) == b'\x01\xc0\x00'

        y_key = storage._to_attr_key(b'y')
        y_raw = storage._trie.get(bytes(y_key))
        assert y_raw == b'\x01' + encode_unsigned_leb128(64) == b'\x01\x40'
