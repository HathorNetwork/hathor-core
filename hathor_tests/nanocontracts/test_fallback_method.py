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

from typing import assert_never
from unittest.mock import ANY

import pytest

from hathor.nanocontracts import HATHOR_TOKEN_UID, NC_EXECUTION_FAIL_ID, Blueprint, Context, NCFail, public
from hathor.nanocontracts.exception import NCInvalidMethodCall
from hathor.nanocontracts.method import ArgsOnly
from hathor.nanocontracts.nc_exec_logs import NCCallBeginEntry, NCCallEndEntry
from hathor.nanocontracts.runner.call_info import CallType
from hathor.nanocontracts.types import ContractId, NCArgs, NCDepositAction, NCParsedArgs, NCRawArgs, TokenUid, fallback
from hathor.transaction import Block, Transaction
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.utils import assert_nc_failure_reason

# TODO: Test support for container args/kwargs such as list[int] after Jan's PR


class MyBlueprint(Blueprint):
    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @fallback(allow_deposit=True)
    def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> str:
        assert method_name == 'unknown'
        match nc_args:
            case NCRawArgs():
                # XXX: we might need to provide a better way to describe the expected signature to `try_parse_as`,
                #      because only looking a a tuple of types might not be enough, currently it is implemented
                #      without the knowledge of default arguments, what this implies is that considering a signature
                #      with types (str, int), it is possible for an empty tuple () to be a valid call, as long as the
                #      function has default values for its two arguments, the parser takes the optimist path and
                #      accepts parsing an empty tuple, so in this case args_bytes=b'\x00' parses to (), because it is
                #      possible that that is a valid call
                result = nc_args.try_parse_as((str, int))
                if result is None:
                    raise NCFail(f'unsupported args: {nc_args}')
                greeting, x = result
                return self.greet_double(ctx, greeting, x)
            case NCParsedArgs(args, kwargs):
                return self.greet_double(ctx, *args, **kwargs)
            case _:
                assert_never(nc_args)

    def greet_double(self, ctx: Context, greeting: str, x: int) -> str:
        return f'{greeting} {x + x}'

    @public(allow_deposit=True)
    def call_another_fallback(self, ctx: Context, contract_id: ContractId) -> str:
        return self.syscall.get_contract(contract_id, blueprint_id=None).public().fallback()

    @public
    def call_own_fallback(self, ctx: Context) -> None:
        # Even though users are not supposed to call the fallback like this, there's no harm and current
        # code allows it, so I'm adding a test to cover it. We may prohibit it in the future.
        nc_args = NCParsedArgs(args=(), kwargs=dict(greeting='hello', x=123))
        self.fallback(ctx, 'unknown', nc_args)


class TestFallbackMethod(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id = self.gen_random_contract_id()

        self.ctx = self.create_context(
            actions=[NCDepositAction(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=123)],
            vertex=self.get_genesis_tx(),
            caller_id=self.gen_random_address(),
            timestamp=self.now,
        )
        self.runner.create_contract(self.contract_id, self.blueprint_id, self.ctx)

    def test_fallback_only_args_success(self) -> None:
        result = self.runner.call_public_method(self.contract_id, 'unknown', self.ctx, 'hello', 123)
        assert result == 'hello 246'

        last_call_info = self.runner.get_last_call_info()
        assert last_call_info.nc_logger.__entries__ == [
            NCCallBeginEntry.construct(
                timestamp=ANY,
                nc_id=self.contract_id,
                call_type=CallType.PUBLIC,
                method_name='fallback',
                str_args="('unknown', NCParsedArgs(args=('hello', 123), kwargs={}))",
                actions=[dict(amount=123, token_uid='00', type='deposit')]
            ),
            NCCallEndEntry.construct(timestamp=ANY),
        ]

    def test_fallback_only_kwargs_success(self) -> None:
        result = self.runner.call_public_method(self.contract_id, 'unknown', self.ctx, greeting='hello', x=123)
        assert result == 'hello 246'

        last_call_info = self.runner.get_last_call_info()
        assert last_call_info.nc_logger.__entries__ == [
            NCCallBeginEntry.construct(
                timestamp=ANY,
                nc_id=self.contract_id,
                call_type=CallType.PUBLIC,
                method_name='fallback',
                str_args="('unknown', NCParsedArgs(args=(), kwargs={'greeting': 'hello', 'x': 123}))",
                actions=[dict(amount=123, token_uid='00', type='deposit')]
            ),
            NCCallEndEntry.construct(timestamp=ANY),
        ]

    def test_fallback_args_kwargs_success(self) -> None:
        result = self.runner.call_public_method(self.contract_id, 'unknown', self.ctx, 'hello', x=123)
        assert result == 'hello 246'

        last_call_info = self.runner.get_last_call_info()
        assert last_call_info.nc_logger.__entries__ == [
            NCCallBeginEntry.construct(
                timestamp=ANY,
                nc_id=self.contract_id,
                call_type=CallType.PUBLIC,
                method_name='fallback',
                str_args="('unknown', NCParsedArgs(args=('hello',), kwargs={'x': 123}))",
                actions=[dict(amount=123, token_uid='00', type='deposit')]
            ),
            NCCallEndEntry.construct(timestamp=ANY),
        ]

    def test_cannot_call_fallback_directly(self) -> None:
        with pytest.raises(NCFail, match='method `fallback` is not a public method'):
            self.runner.call_public_method(self.contract_id, 'fallback', self.ctx)

    def test_cannot_call_another_fallback_directly(self) -> None:
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, self.blueprint_id, self.ctx)
        with pytest.raises(NCInvalidMethodCall, match='method `fallback` is not a public method'):
            self.runner.call_public_method(self.contract_id, 'call_another_fallback', self.ctx, contract_id)

    def test_fallback_args_bytes_success(self) -> None:
        args_parser = ArgsOnly.from_arg_types((str, int))
        args_bytes = args_parser.serialize_args_bytes(('hello', 123))
        nc_args = NCRawArgs(args_bytes)
        result = self.runner.call_public_method_with_nc_args(self.contract_id, 'unknown', self.ctx, nc_args)
        assert result == 'hello 246'

        last_call_info = self.runner.get_last_call_info()
        assert last_call_info.nc_logger.__entries__ == [
            NCCallBeginEntry.construct(
                timestamp=ANY,
                nc_id=self.contract_id,
                call_type=CallType.PUBLIC,
                method_name='fallback',
                str_args=f"('unknown', NCRawArgs('{args_bytes.hex()}'))",
                actions=[dict(amount=123, token_uid='00', type='deposit')]
            ),
            NCCallEndEntry.construct(timestamp=ANY),
        ]

    def test_dag_fallback(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        valid_args_parser = ArgsOnly.from_arg_types((str, int))
        valid_args_bytes = valid_args_parser.serialize_args_bytes(('hello', 123))
        invalid_args_parser = ArgsOnly.from_arg_types((int, int))
        invalid_args_bytes = invalid_args_parser.serialize_args_bytes((123, 456))

        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = nc1
            nc2.nc_method = unknown
            nc2.nc_args_bytes = "{valid_args_bytes.hex()}"

            nc3.nc_id = nc1
            nc3.nc_method = unknown
            nc3.nc_args_bytes = "{invalid_args_bytes.hex()}"

            nc1 <-- nc2 <-- nc3 <-- b11
        ''')

        artifacts.propagate_with(self.manager)
        b11 = artifacts.get_typed_vertex('b11', Block)
        nc1, nc2, nc3 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3'], Transaction)

        assert b11.get_metadata().voided_by is None
        assert nc1.get_metadata().voided_by is None

        # nc2 successfully executes because the nc_args_bytes is correct
        assert nc2.get_metadata().voided_by is None

        # nc3 fails because the fallback method is not expecting these args_bytes
        assert nc3.get_metadata().voided_by == {nc3.hash, NC_EXECUTION_FAIL_ID}
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=nc3.hash,
            block_id=b11.hash,
            reason=f'NCFail: unsupported args: {invalid_args_bytes.hex()}',
        )

    def test_call_own_fallback(self) -> None:
        self.runner.call_public_method(self.contract_id, 'call_own_fallback', self.create_context())
