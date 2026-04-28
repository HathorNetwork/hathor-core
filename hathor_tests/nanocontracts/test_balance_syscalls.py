# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor import Blueprint, Context, ContractId, TokenUid, public
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    token_uid: TokenUid

    @public
    def initialize(self, ctx: Context, token_uid: TokenUid) -> None:
        self.token_uid = token_uid

    @public
    def test_balance_syscalls_on_self(self, ctx: Context) -> None:
        assert self.syscall.get_current_balance() == 0
        assert self.syscall.get_balance_before_current_call() == 0

        assert not self.syscall.can_mint(self.token_uid)
        assert not self.syscall.can_mint_before_current_call(self.token_uid)

        assert not self.syscall.can_melt(self.token_uid)
        assert not self.syscall.can_melt_before_current_call(self.token_uid)

    @public
    def test_balance_syscalls_on_another(self, ctx: Context, other_id: ContractId) -> None:
        contract = self.syscall.get_contract(other_id, blueprint_id=None)
        assert contract.get_current_balance() == 0
        assert not contract.can_mint(self.token_uid)
        assert not contract.can_melt(self.token_uid)


class BalanceSyscallsTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id1 = self.gen_random_contract_id()
        self.contract_id2 = self.gen_random_contract_id()

        token_uid = self.gen_random_token_uid()
        self.runner.create_contract(self.contract_id1, self.blueprint_id, self.create_context(), token_uid)
        self.runner.create_contract(self.contract_id2, self.blueprint_id, self.create_context(), token_uid)

    def test_balance_syscalls_on_self(self) -> None:
        self.runner.call_public_method(self.contract_id1, 'test_balance_syscalls_on_self', self.create_context())

    def test_balance_syscalls_on_another(self) -> None:
        self.runner.call_public_method(
            self.contract_id1,
            'test_balance_syscalls_on_another',
            self.create_context(),
            self.contract_id2,
        )
