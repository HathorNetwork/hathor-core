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
from hathor.nanocontracts.types import Address, Amount, BlueprintId, ContractId, TokenUid, VertexId
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class DirectSyscalls(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

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
    def get_current_code_blueprint_id(self) -> None:
        self.syscall.get_current_code_blueprint_id()

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
    def revoke_authorities(self) -> None:
        self.syscall.revoke_authorities(TokenUid(b''), revoke_mint=True, revoke_melt=True)

    @view
    def mint_tokens(self) -> None:
        self.syscall.mint_tokens(TokenUid(b''), amount=0)

    @view
    def melt_tokens(self) -> None:
        self.syscall.melt_tokens(TokenUid(b''), amount=0)

    @view
    def emit_event(self) -> None:
        self.syscall.emit_event(b'')

    @view
    def create_deposit_token(self) -> None:
        self.syscall.create_deposit_token(token_name='', token_symbol='', amount=0)

    @view
    def create_fee_token(self) -> None:
        self.syscall.create_fee_token(token_name='', token_symbol='', amount=0)

    @view
    def change_blueprint(self) -> None:
        self.syscall.change_blueprint(BlueprintId(VertexId(b'')))

    @view
    def get_contract(self) -> None:
        self.syscall.get_contract(ContractId(b''), blueprint_id=None)

    @view
    def get_proxy(self) -> None:
        self.syscall.get_proxy(BlueprintId(VertexId(b'')))

    @view
    def setup_new_contract(self) -> None:
        self.syscall.setup_new_contract(BlueprintId(VertexId(b'')), salt=b'')

    @view
    def transfer_to_address(self) -> None:
        self.syscall.transfer_to_address(Address(b''), amount=Amount(0), token=TokenUid(b''))


class IndirectSyscalls(Blueprint):
    other_blueprint_id: BlueprintId | None
    other_contract_id: ContractId | None

    @public
    def initialize(
        self,
        ctx: Context,
        other_blueprint_id: BlueprintId | None,
        other_contract_id: ContractId | None,
    ) -> None:
        self.other_blueprint_id = other_blueprint_id
        self.other_contract_id = other_contract_id

    @view
    def nop(self) -> None:
        pass

    @view
    def call_public_method(self) -> None:
        self.syscall.get_contract(ContractId(VertexId(b'')), blueprint_id=None).public().nop()

    @view
    def call_view_method(self) -> None:
        assert self.other_contract_id is not None
        self.syscall.get_contract(self.other_contract_id, blueprint_id=None).view().nop()

    @view
    def setup_new_contract(self) -> None:
        self.syscall.setup_new_contract(BlueprintId(VertexId(b'')), salt=b'').initialize()

    @view
    def proxy_call_view_method(self) -> None:
        assert self.other_blueprint_id is not None
        self.syscall.get_proxy(self.other_blueprint_id).view().nop()

    @view
    def proxy_call_public_method(self) -> None:
        self.syscall.get_proxy(BlueprintId(VertexId(b''))).public().nop()


class TestSyscallsInView(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id1 = self._register_blueprint_class(DirectSyscalls)
        self.blueprint_id2 = self._register_blueprint_class(IndirectSyscalls)

    def test_rng(self) -> None:
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, self.blueprint_id1, self.create_context())

        with pytest.raises(NCViewMethodError, match='@view method cannot call `syscall.rng`'):
            self.runner.call_view_method(contract_id, 'test_rng')

    def test_direct_syscalls(self) -> None:
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, self.blueprint_id1, self.create_context())

        properties = {'rng'}  # each property must be tested specifically
        allowed_view_syscalls = {
            'get_contract_id',
            'get_blueprint_id',
            'get_balance_before_current_call',
            'get_current_balance',
            'can_mint',
            'can_mint_before_current_call',
            'can_melt',
            'can_melt_before_current_call',
            'get_contract',
            'get_proxy',
            'get_current_code_blueprint_id',
        }

        tested_methods = set()
        for method_name, method in BlueprintEnvironment.__dict__.items():
            if '__' in method_name or method_name in properties:
                continue

            tested_methods.add(method_name)
            if method_name in allowed_view_syscalls:
                self.runner.call_view_method(contract_id, method_name)
            else:
                with pytest.raises(NCViewMethodError, match=f'@view method cannot call `syscall.{method_name}`'):
                    self.runner.call_view_method(contract_id, method_name)

        skip_tested_methods = {'initialize', 'nop', 'test_rng'}
        for method_name, method in DirectSyscalls.__dict__.items():
            if '__' in method_name or method_name in skip_tested_methods:
                continue
            assert method_name in tested_methods, f'method `{method_name}` of DirectSyscalls was not tested'

        for method_name in allowed_view_syscalls:
            assert method_name in tested_methods, f'method `{method_name}` of `allowed_view_syscalls` was not tested'

    def test_indirect_syscalls(self) -> None:
        contract_id1 = self.gen_random_contract_id()
        contract_id2 = self.gen_random_contract_id()

        self.runner.create_contract(contract_id1, self.blueprint_id2, self.create_context(), None, None)
        self.runner.create_contract(
            contract_id2, self.blueprint_id2, self.create_context(), self.blueprint_id1, contract_id1
        )

        self.runner.call_view_method(contract_id2, 'call_view_method')
        self.runner.call_view_method(contract_id2, 'proxy_call_view_method')

        with pytest.raises(NCViewMethodError, match='@view method cannot call `syscall.call_public_method`'):
            self.runner.call_view_method(contract_id2, 'call_public_method')

        with pytest.raises(NCViewMethodError, match='@view method cannot call `syscall.setup_new_contract`'):
            self.runner.call_view_method(contract_id2, 'setup_new_contract')

        with pytest.raises(NCViewMethodError, match='@view method cannot call `syscall.proxy_call_public_method`'):
            self.runner.call_view_method(contract_id2, 'proxy_call_public_method')
