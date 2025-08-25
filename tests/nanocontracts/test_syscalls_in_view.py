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

import pytest

from hathor.nanocontracts import Blueprint, Context, public, view
from hathor.nanocontracts.blueprint_env import BlueprintEnvironment
from hathor.nanocontracts.exception import NCViewMethodError
from hathor.nanocontracts.types import BlueprintId, ContractId, NCRawArgs, TokenUid, VertexId
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    other_id: ContractId | None

    @public
    def initialize(self, ctx: Context, other_id: ContractId | None) -> None:
        self.other_id = other_id

    @view
    def nop(self) -> None:
        pass

    @view
    def test_rng(self) -> None:
        self.syscall.rng.randbits(1)

    @view
    def get_contract_id(self) -> None:
        self.syscall.get_contract_id()

    @view
    def get_blueprint_id(self) -> None:
        self.syscall.get_blueprint_id()

    @view
    def get_balance_before_current_call(self) -> None:
        self.syscall.get_balance_before_current_call()

    @view
    def get_current_balance(self) -> None:
        self.syscall.get_current_balance()

    @view
    def can_mint(self) -> None:
        self.syscall.can_mint(TokenUid(b''))

    @view
    def can_mint_before_current_call(self) -> None:
        self.syscall.can_mint_before_current_call(TokenUid(b''))

    @view
    def can_melt(self) -> None:
        self.syscall.can_melt(TokenUid(b''))

    @view
    def can_melt_before_current_call(self) -> None:
        self.syscall.can_melt_before_current_call(TokenUid(b''))

    @view
    def call_public_method(self) -> None:
        self.syscall.call_public_method(ContractId(VertexId(b'')), '', [])

    @view
    def call_view_method(self) -> None:
        assert self.other_id is not None
        self.syscall.call_view_method(self.other_id, 'nop')

    @view
    def revoke_authorities(self) -> None:
        self.syscall.revoke_authorities(TokenUid(b''), revoke_mint=True, revoke_melt=True)

    @view
    def mint_tokens(self) -> None:
        self.syscall.mint_tokens(TokenUid(b''), 0)

    @view
    def melt_tokens(self) -> None:
        self.syscall.melt_tokens(TokenUid(b''), 0)

    @view
    def create_contract(self) -> None:
        self.syscall.create_contract(BlueprintId(VertexId(b'')), b'', [])

    @view
    def emit_event(self) -> None:
        self.syscall.emit_event(b'')

    @view
    def create_token(self) -> None:
        self.syscall.create_token('', '', 0)

    @view
    def proxy_call_public_method(self) -> None:
        self.syscall.proxy_call_public_method(BlueprintId(VertexId(b'')), '', [])

    @view
    def proxy_call_public_method_nc_args(self) -> None:
        nc_args = NCRawArgs(b'')
        self.syscall.proxy_call_public_method_nc_args(BlueprintId(VertexId(b'')), '', [], nc_args)

    @view
    def change_blueprint(self) -> None:
        self.syscall.change_blueprint(BlueprintId(VertexId(b'')))

    @view
    def get_contract(self) -> None:
        self.syscall.get_contract(ContractId(b''), blueprint_id=None)


class TestSyscallsInView(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self._register_blueprint_class(MyBlueprint)

        self.ctx = self.create_context(
            actions=[],
            vertex=self.get_genesis_tx(),
            caller_id=self.gen_random_address(),
            timestamp=self.now,
        )

    def test_rng(self) -> None:
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, self.blueprint_id, self.ctx, None)

        with pytest.raises(NCViewMethodError, match='@view method cannot call `syscall.rng`'):
            self.runner.call_view_method(contract_id, 'test_rng')

    def test_syscalls(self) -> None:
        other_id = self.gen_random_contract_id()
        self.runner.create_contract(other_id, self.blueprint_id, self.ctx, None)

        properties = {'rng'}  # each property must be tested specifically
        allowed_view_syscalls = {
            'get_contract_id',
            'get_blueprint_id',
            'get_balance',
            'get_balance_before_current_call',
            'get_current_balance',
            'can_mint',
            'can_mint_before_current_call',
            'can_melt',
            'can_melt_before_current_call',
            'call_view_method',
            'get_contract'
        }

        for method_name, method in BlueprintEnvironment.__dict__.items():
            if '__' in method_name or method_name in properties:
                continue

            contract_id = self.gen_random_contract_id()
            self.runner.create_contract(contract_id, self.blueprint_id, self.ctx, other_id)

            if method_name in allowed_view_syscalls:
                self.runner.call_view_method(contract_id, method_name)
            else:
                with pytest.raises(NCViewMethodError, match=f'@view method cannot call `syscall.{method_name}`'):
                    self.runner.call_view_method(contract_id, method_name)
