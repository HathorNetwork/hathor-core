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
from hathor.nanocontracts.types import (
    BlueprintId,
    ContractId,
    NCArgs,
    NCDepositAction,
    VertexId,
    fallback,
    public,
    view,
)


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
        contract = self.syscall.get_contract(other_id, blueprint_id=None)
        return contract \
            .view() \
            .simple_view_method(name)

    @public
    def test_simple_public_method(self, ctx: Context, other_id: ContractId, name: str) -> str:
        contract = self.syscall.get_contract(other_id, blueprint_id=None)
        return contract \
            .public(NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID)) \
            .simple_public_method(name)

    @public
    def test_simple_public_method_no_actions(self, ctx: Context, other_id: ContractId, name: str) -> str:
        contract = self.syscall.get_contract(other_id, blueprint_id=None)
        return contract \
            .public() \
            .simple_public_method(name)

    @view
    def test_multiple_view_calls_on_prepared_call(self, other_id: ContractId, name: str) -> tuple[str, str]:
        prepared_call = self.syscall.get_contract(other_id, blueprint_id=None) \
            .view()
        ret1 = prepared_call.simple_view_method(name + '1')
        ret2 = prepared_call.simple_view_method(name + '2')
        return ret1, ret2

    @view
    def test_multiple_view_calls_on_method(self, other_id: ContractId, name: str) -> tuple[str, str]:
        prepared_call = self.syscall.get_contract(other_id, blueprint_id=None) \
            .view()
        method = prepared_call.simple_view_method
        ret1 = method(name + '1')
        ret2 = method(name + '2')
        return ret1, ret2

    @public
    def test_multiple_public_calls_on_prepared_call(
        self,
        ctx: Context,
        other_id: ContractId,
        name: str,
    ) -> tuple[str, str]:
        prepared_call = self.syscall.get_contract(other_id, blueprint_id=None) \
            .public(NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID))
        ret1 = prepared_call.simple_public_method(name + '1')
        ret2 = prepared_call.simple_public_method(name + '2')
        return ret1, ret2

    @public
    def test_multiple_public_calls_on_method(
        self,
        ctx: Context,
        other_id: ContractId,
        name: str,
    ) -> tuple[str, str]:
        prepared_call = self.syscall.get_contract(other_id, blueprint_id=None) \
            .public(NCDepositAction(amount=123, token_uid=HATHOR_TOKEN_UID))
        method = prepared_call.simple_public_method
        ret1 = method(name + '1')
        ret2 = method(name + '2')
        return ret1, ret2

    @public
    def test_fallback_allowed(self, ctx: Context, other_id: ContractId) -> str:
        contract = self.syscall.get_contract(other_id, blueprint_id=None)
        return contract \
            .public() \
            .unknown()

    @public
    def test_fallback_forbidden(self, ctx: Context, other_id: ContractId) -> str:
        contract = self.syscall.get_contract(other_id, blueprint_id=None)
        return contract \
            .public(forbid_fallback=True) \
            .unknown()

    @view
    def test_view_allow_single_blueprint_valid(self, other_id: ContractId, name: str) -> str:
        my_blueprint_id = self.syscall.get_blueprint_id()
        contract = self.syscall.get_contract(other_id, blueprint_id=my_blueprint_id)
        return contract \
            .view() \
            .simple_view_method(name)

    @view
    def test_view_allow_single_blueprint_invalid(self, other_id: ContractId, name: str) -> str:
        blueprint_id = BlueprintId(VertexId(b'\x11' * 32))
        contract = self.syscall.get_contract(other_id, blueprint_id=blueprint_id)
        return contract \
            .view() \
            .simple_view_method(name)

    @view
    def test_view_allow_multiple_blueprints_valid(self, other_id: ContractId, name: str) -> str:
        blueprint_id = BlueprintId(VertexId(b'\x11' * 32))
        my_blueprint_id = self.syscall.get_blueprint_id()
        contract = self.syscall.get_contract(other_id, blueprint_id=(blueprint_id, my_blueprint_id))
        return contract \
            .view() \
            .simple_view_method(name)

    @view
    def test_view_allow_multiple_blueprints_invalid(self, other_id: ContractId, name: str) -> str:
        blueprint_id1 = BlueprintId(VertexId(b'\x11' * 32))
        blueprint_id2 = BlueprintId(VertexId(b'\x22' * 32))
        contract = self.syscall.get_contract(other_id, blueprint_id=(blueprint_id1, blueprint_id2))
        return contract \
            .view() \
            .simple_view_method(name)

    @public
    def test_public_allow_single_blueprint_valid(self, ctx: Context, other_id: ContractId, name: str) -> str:
        my_blueprint_id = self.syscall.get_blueprint_id()
        contract = self.syscall.get_contract(other_id, blueprint_id=my_blueprint_id)
        return contract \
            .public() \
            .simple_public_method(name)

    @public
    def test_public_allow_single_blueprint_invalid(self, ctx: Context, other_id: ContractId, name: str) -> str:
        blueprint_id = BlueprintId(VertexId(b'\x11' * 32))
        contract = self.syscall.get_contract(other_id, blueprint_id=blueprint_id)
        return contract \
            .public() \
            .simple_public_method(name)

    @public
    def test_public_allow_multiple_blueprints_valid(self, ctx: Context, other_id: ContractId, name: str) -> str:
        blueprint_id = BlueprintId(VertexId(b'\x11' * 32))
        my_blueprint_id = self.syscall.get_blueprint_id()
        contract = self.syscall.get_contract(other_id, blueprint_id=(blueprint_id, my_blueprint_id))
        return contract \
            .public() \
            .simple_public_method(name)

    @public
    def test_public_allow_multiple_blueprints_invalid(self, ctx: Context, other_id: ContractId, name: str) -> str:
        blueprint_id1 = BlueprintId(VertexId(b'\x11' * 32))
        blueprint_id2 = BlueprintId(VertexId(b'\x22' * 32))
        contract = self.syscall.get_contract(other_id, blueprint_id=(blueprint_id1, blueprint_id2))
        return contract \
            .public() \
            .simple_public_method(name)

    @fallback
    def fallback(self, ctx: Context, method_name: str, nc_args: NCArgs) -> str:
        return f'fallback called for method `{method_name}`'


__blueprint__ = MyBlueprint
