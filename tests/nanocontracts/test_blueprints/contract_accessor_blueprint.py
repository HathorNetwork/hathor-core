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

from hathor.nanocontracts import HATHOR_TOKEN_UID, Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import ContractId, NCDepositAction, public, view


class MyBlueprint(Blueprint):
    message: str

    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        self.message = 'initialize called'

    def internal_method(self) -> None:
        pass

    @view
    def simple_view_method(self, name: str) -> str:
        return f'hello "{name}" from simple view method'

    @public(allow_deposit=True)
    def simple_public_method(self, ctx: Context, name: str) -> str:
        actions = ctx.actions.get(HATHOR_TOKEN_UID, ())

        # Setting the attribute makes it easier to test on OCBs with the DagBuilder,
        # as the returned value is not accessible.
        self.message = f'hello "{name}" from simple public method with actions: {actions}'

        return self.message

    @view
    def test_simple_view_method(self, other_id: ContractId, name: str) -> str:
        contract = self.syscall.get_contract(other_id)
        return contract.simple_view_method(name)

    @public
    def test_simple_public_method(self, ctx: Context, other_id: ContractId, name: str) -> str:
        contract = self.syscall.get_contract(other_id)
        return contract \
            .use_actions(NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)) \
            .simple_public_method(name)

    @public
    def test_simple_public_method_no_actions(self, ctx: Context, other_id: ContractId, name: str) -> str:
        contract = self.syscall.get_contract(other_id)
        return contract.simple_public_method(name)

    @view
    def test_multiple_view_calls_on_contract(self, other_id: ContractId, name: str) -> tuple[str, str]:
        contract = self.syscall.get_contract(other_id)
        ret1 = contract.simple_view_method(name + '1')
        ret2 = contract.simple_view_method(name + '2')
        return ret1, ret2

    @view
    def test_multiple_view_calls_on_method(self, other_id: ContractId, name: str) -> tuple[str, str]:
        contract = self.syscall.get_contract(other_id)
        method = contract.simple_view_method
        ret1 = method(name + '1')
        ret2 = method(name + '2')
        return ret1, ret2

    @public
    def test_actions_clear_after_single_use(self, ctx: Context, other_id: ContractId, name: str) -> tuple[str, str]:
        contract = self.syscall.get_contract(other_id) \
            .use_actions(NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID))
        ret1 = contract.simple_public_method(name + '1')
        ret2 = contract.simple_public_method(name + '2')
        return ret1, ret2

    @public
    def test_multiple_public_calls_on_method(
        self,
        ctx: Context,
        other_id: ContractId,
        name: str,
    ) -> tuple[str, str]:
        contract = self.syscall.get_contract(other_id) \
            .use_actions(NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID))
        method = contract.simple_public_method
        ret1 = method(name + '1')
        ret2 = method(name + '2')
        return ret1, ret2

    @public
    def test_multiple_public_calls_on_method_no_actions(
        self,
        ctx: Context,
        other_id: ContractId,
        name: str,
    ) -> tuple[str, str]:
        contract = self.syscall.get_contract(other_id)
        method = contract.simple_public_method
        ret1 = method(name + '1')
        ret2 = method(name + '2')
        return ret1, ret2

    @public
    def test_unused_actions_already_set(self, ctx: Context, other_id: ContractId, name: str) -> str:
        contract = self.syscall.get_contract(other_id)
        return contract \
            .use_actions(NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)) \
            .use_actions(NCDepositAction(amount=456, token_uid=HATHOR_TOKEN_UID)) \
            .simple_public_method(name)

    @public
    def test_forbidden_initialize(self, ctx: Context, other_id: ContractId) -> str:
        contract = self.syscall.get_contract(other_id)
        return contract.initialize()

    @public
    def test_forbidden_fallback(self, ctx: Context, other_id: ContractId) -> str:
        contract = self.syscall.get_contract(other_id)
        return contract.fallback()

    @public
    def test_unknown_method(self, ctx: Context, other_id: ContractId) -> str:
        contract = self.syscall.get_contract(other_id)
        return contract.unknown()

    @public
    def test_call_attr(self, ctx: Context, other_id: ContractId) -> str:
        contract = self.syscall.get_contract(other_id)
        return contract.message()

    @public
    def test_internal_method(self, ctx: Context, other_id: ContractId) -> str:
        contract = self.syscall.get_contract(other_id)
        return contract.internal_method()

    @public
    def test_view_with_actions(self, ctx: Context, other_id: ContractId, name: str) -> str:
        contract = self.syscall.get_contract(other_id)
        return contract \
            .use_actions(NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)) \
            .simple_view_method(name)


__blueprint__ = MyBlueprint
