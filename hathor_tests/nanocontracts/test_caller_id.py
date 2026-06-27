# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.types import Address, BlueprintId, CallerId, ContractId
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    address: Address | None
    contract_id: ContractId | None
    caller_id: CallerId

    @public
    def initialize(self, ctx: Context) -> None:
        self.caller_id = ctx.caller_id

        if address := ctx.get_caller_address():
            self.address = address
            self.contract_id = None
        elif contract_id := ctx.get_caller_contract_id():
            self.address = None
            self.contract_id = contract_id
        else:
            raise AssertionError

    @public
    def create_another(self, ctx: Context, blueprint_id: BlueprintId) -> ContractId:
        contract_id, _ = self.syscall.setup_new_contract(blueprint_id, salt=b'1').initialize()
        return contract_id

    @public
    def test_args_and_return(self, ctx: Context, caller_id: CallerId) -> CallerId:
        return caller_id


class TestCallerId(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id1 = self.gen_random_contract_id()

    def test_callers(self) -> None:
        address = self.gen_random_address()
        ctx = self.create_context(caller_id=address)
        self.runner.create_contract(self.contract_id1, self.blueprint_id, ctx)
        contract1 = self.get_readonly_contract(self.contract_id1)

        # Caller is an address (a tx)
        assert isinstance(contract1, MyBlueprint)
        assert contract1.address == address
        assert contract1.contract_id is None
        assert contract1.caller_id == address

        contract_id2 = self.runner.call_public_method(self.contract_id1, 'create_another', ctx, self.blueprint_id)
        contract2 = self.get_readonly_contract(contract_id2)

        # Caller is another contract
        assert isinstance(contract2, MyBlueprint)
        assert contract2.address is None
        assert contract2.contract_id == self.contract_id1
        assert contract2.caller_id == self.contract_id1

    def test_args_and_return(self) -> None:
        self.runner.create_contract(self.contract_id1, self.blueprint_id, self.create_context())

        # Receive and return an address
        address = self.gen_random_address()
        ret = self.runner.call_public_method(
            self.contract_id1, 'test_args_and_return', self.create_context(), address
        )
        assert ret == address

        # Receive and return a contract id
        contract_id = self.gen_random_contract_id()
        ret = self.runner.call_public_method(
            self.contract_id1, 'test_args_and_return', self.create_context(), contract_id
        )
        assert ret == contract_id
