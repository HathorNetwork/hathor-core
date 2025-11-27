#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import BlueprintSyntaxError
from hathor.nanocontracts.types import BlueprintId, VertexId, public
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.test_blueprints.all_fields import AllFieldsBlueprint


class TestAllFields(unittest.TestCase):
    def test_all_fields_builtin(self) -> None:
        manager = self.create_peer('unittests')
        blueprint_id = BlueprintId(VertexId(b'\x01' * 32))
        manager.tx_storage.nc_catalog.blueprints[blueprint_id] = AllFieldsBlueprint

        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            nc1.nc_id = "{blueprint_id.hex()}"
            nc1.nc_method = initialize()
            nc1 <-- b11
        ''')
        artifacts.propagate_with(manager)

        b11 = artifacts.get_typed_vertex('b11', Block)
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)

        assert b11.get_metadata().voided_by is None

        assert nc1.get_metadata().voided_by is None
        assert nc1.get_metadata().first_block == b11.hash
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS

    def test_all_fields_ocb(self) -> None:
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        manager = self.create_peer('unittests')
        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"
            ocb1.ocb_code = all_fields.py, AllFieldsBlueprint
            ocb1 <-- b11

            nc1.nc_id = ocb1
            nc1.nc_method = initialize()
            nc1 <-- b12
        ''')
        artifacts.propagate_with(manager)

        b11, b12 = artifacts.get_typed_vertices(['b11', 'b12'], Block)
        ocb1 = artifacts.get_typed_vertex('ocb1', OnChainBlueprint)
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)

        assert b11.get_metadata().voided_by is None

        assert ocb1.get_metadata().voided_by is None
        assert ocb1.get_metadata().first_block == b11.hash

        assert nc1.get_metadata().voided_by is None
        assert nc1.get_metadata().first_block == b12.hash
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS

    def test_no_named_tuple_type(self) -> None:
        from typing import NamedTuple

        with self.assertRaises(BlueprintSyntaxError) as cm:
            class MyInvalidBlueprint(Blueprint):
                invalid_attribute: NamedTuple

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

        assert cm.exception.args[0] == 'unsupported field type: `invalid_attribute: NamedTuple`'
        context_exception = cm.exception.__context__
        assert isinstance(context_exception, TypeError)
        assert context_exception.args[0] == 'issubclass() arg 1 must be a class'

    def test_no_bytearray(self) -> None:
        with self.assertRaises(BlueprintSyntaxError) as cm:
            class MyInvalidBlueprint(Blueprint):
                invalid_attribute: bytearray

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

        assert cm.exception.args[0] == 'unsupported field type: `invalid_attribute: bytearray`'
        context_exception = cm.exception.__context__
        assert isinstance(context_exception, TypeError)
        assert context_exception.args[0] == r"type <class 'bytearray'> is not supported by any NCType class"

    def test_no_typing_union(self) -> None:
        from typing import Union

        with self.assertRaises(BlueprintSyntaxError) as cm:
            class MyInvalidBlueprint(Blueprint):
                invalid_attribute: Union[str, int]

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

        assert cm.exception.args[0] == 'unsupported field type: `invalid_attribute: typing.Union[str, int]`'
        context_exception = cm.exception.__context__
        assert isinstance(context_exception, TypeError)
        assert context_exception.args[0] == r"type typing.Union[str, int] is not supported by any NCType class"

    def test_no_union_type(self) -> None:
        with self.assertRaises(BlueprintSyntaxError) as cm:
            class MyInvalidBlueprint(Blueprint):
                invalid_attribute: str | int

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

        assert cm.exception.args[0] == 'unsupported field type: `invalid_attribute: str | int`'
        context_exception = cm.exception.__context__
        assert isinstance(context_exception, TypeError)
        assert context_exception.args[0] == r"type str | int is not supported by any NCType class"

    def test_no_none(self) -> None:
        with self.assertRaises(BlueprintSyntaxError) as cm:
            class MyInvalidBlueprint(Blueprint):
                invalid_attribute: None

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

        assert cm.exception.args[0] == 'unsupported field type: `invalid_attribute: None`'
        context_exception = cm.exception.__context__
        assert isinstance(context_exception, TypeError)
        assert context_exception.args[0] == r"type None is not supported by any NCType class"

    def test_no_dict_inside_tuple(self) -> None:
        with self.assertRaises(BlueprintSyntaxError) as cm:
            class MyInvalidBlueprint(Blueprint):
                invalid_attribute: tuple[dict[str, int]]

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

        assert cm.exception.args[0] == 'unsupported field type: `invalid_attribute: tuple[dict[str, int]]`'
        context_exception = cm.exception.__context__
        assert isinstance(context_exception, TypeError)
        assert context_exception.args[0] == r"type dict[str, int] is not supported by any NCType class"

    def test_no_dict_inside_namedtuple(self) -> None:
        from typing import NamedTuple

        class Inner(NamedTuple):
            data: dict[str, int]

        with self.assertRaises(BlueprintSyntaxError) as cm:
            class MyInvalidBlueprint(Blueprint):
                invalid_attribute: Inner

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

        assert cm.exception.args[0] == 'unsupported field type: `invalid_attribute: Inner`'
        context_exception = cm.exception.__context__
        assert isinstance(context_exception, TypeError)
        assert context_exception.args[0] == r"type dict[str, int] is not supported by any NCType class"

    def test_no_list_inside_tuple(self) -> None:
        with self.assertRaises(BlueprintSyntaxError) as cm:
            class MyInvalidBlueprint(Blueprint):
                invalid_attribute: tuple[list[int]]

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

        assert cm.exception.args[0] == 'unsupported field type: `invalid_attribute: tuple[list[int]]`'
        context_exception = cm.exception.__context__
        assert isinstance(context_exception, TypeError)
        assert context_exception.args[0] == r"type list[int] is not supported by any NCType class"

    def test_no_set_inside_tuple(self) -> None:
        with self.assertRaises(BlueprintSyntaxError) as cm:
            class MyInvalidBlueprint(Blueprint):
                invalid_attribute: tuple[set[int]]

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

        assert cm.exception.args[0] == 'unsupported field type: `invalid_attribute: tuple[set[int]]`'
        context_exception = cm.exception.__context__
        assert isinstance(context_exception, TypeError)
        assert context_exception.args[0] == r"type set[int] is not supported by any NCType class"

    def test_no_list_inside_namedtuple(self) -> None:
        from typing import NamedTuple

        class Inner(NamedTuple):
            data: list[int]

        with self.assertRaises(BlueprintSyntaxError) as cm:
            class MyInvalidBlueprint(Blueprint):
                invalid_attribute: Inner

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

        assert cm.exception.args[0] == 'unsupported field type: `invalid_attribute: Inner`'
        context_exception = cm.exception.__context__
        assert isinstance(context_exception, TypeError)
        assert context_exception.args[0] == r"type list[int] is not supported by any NCType class"

    def test_no_set_inside_namedtuple(self) -> None:
        from typing import NamedTuple

        class Inner(NamedTuple):
            data: set[int]

        with self.assertRaises(BlueprintSyntaxError) as cm:
            class MyInvalidBlueprint(Blueprint):
                invalid_attribute: Inner

                @public
                def initialize(self, ctx: Context) -> None:
                    pass

        assert cm.exception.args[0] == 'unsupported field type: `invalid_attribute: Inner`'
        context_exception = cm.exception.__context__
        assert isinstance(context_exception, TypeError)
        assert context_exception.args[0] == r"type set[int] is not supported by any NCType class"
