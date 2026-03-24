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

from hathor import (
    HATHOR_TOKEN_UID,
    Amount,
    Blueprint,
    Context,
    ContractId,
    NCDepositAction,
    NCFail,
    NCWithdrawalAction,
    TokenUid,
    public,
)
from hathor.nanocontracts.exception import NCInsufficientFunds
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class LoanNotFullyPaid(NCFail):
    pass


class FlashLoan(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_withdrawal=True)
    def withdrawal(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True, allow_reentrancy=True)
    def deposit(self, ctx: Context) -> None:
        pass

    @public
    def call(self, ctx: Context, contract_id: ContractId, method_name: str, amount: Amount) -> None:
        initial_balance = self.syscall.get_current_balance(HATHOR_TOKEN_UID)
        my_nc_id = self.syscall.get_contract_id()

        contract = self.syscall.get_contract(contract_id, blueprint_id=None)
        action = NCDepositAction(amount=amount, token_uid=HATHOR_TOKEN_UID)
        method = contract.get_public_method(method_name, action)
        method(my_nc_id)

        final_balance = self.syscall.get_current_balance(HATHOR_TOKEN_UID)
        if initial_balance != final_balance:
            raise LoanNotFullyPaid('flash loans must be paid back before the end of the call')


class UseFlashLoan(Blueprint):
    flashloan_id: ContractId

    @public
    def initialize(self, ctx: Context, flashloan_id: ContractId) -> None:
        self.flashloan_id = flashloan_id

    @public(allow_deposit=True)
    def nop(self, ctx: Context, loan_id: ContractId) -> None:
        action = ctx.get_single_action(HATHOR_TOKEN_UID)
        assert isinstance(action, NCDepositAction)
        assert action.amount == self.syscall.get_current_balance(HATHOR_TOKEN_UID)

    @public(allow_deposit=True)
    def nop_payback(self, ctx: Context, loan_id: ContractId) -> None:
        action = ctx.get_single_action(HATHOR_TOKEN_UID)
        assert isinstance(action, NCDepositAction)
        assert action.amount == self.syscall.get_current_balance(action.token_uid)

        contract = self.syscall.get_contract(loan_id, blueprint_id=None)
        action = NCDepositAction(amount=action.amount, token_uid=action.token_uid)
        contract.public(action).deposit()

    @public
    def run(self, ctx: Context, amount: Amount, token_uid: TokenUid) -> None:
        flashloan = self.syscall.get_contract(self.flashloan_id, blueprint_id=None)
        withdrawal_action = NCWithdrawalAction(amount=amount, token_uid=token_uid)
        flashloan.public(withdrawal_action).withdrawal()

        # amount was added to this contract balance, so we can use it as we wish
        # as long as we deposit it back in this call
        assert amount == self.syscall.get_current_balance(token_uid)

        deposit_action = NCDepositAction(amount=amount, token_uid=token_uid)
        flashloan.public(deposit_action).deposit()


class TestNegativeBalance(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.flash_bp_id = self._register_blueprint_class(FlashLoan)
        self.use_bp_id = self._register_blueprint_class(UseFlashLoan)

        self.flash_nc_id = self.gen_random_contract_id()
        self.use_nc_id = self.gen_random_contract_id()

    def test_withdrawal_no_balance(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.flash_nc_id, self.flash_bp_id, ctx)

        ctx = self.create_context(actions=[
            NCWithdrawalAction(amount=100, token_uid=HATHOR_TOKEN_UID),
        ])
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(self.flash_nc_id, 'withdrawal', ctx)

    def test_deposit_withdrawal(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.flash_nc_id, self.flash_bp_id, ctx)

        ctx = self.create_context(actions=[
            NCDepositAction(amount=200, token_uid=HATHOR_TOKEN_UID),
        ])
        self.runner.call_public_method(self.flash_nc_id, 'deposit', ctx)

        ctx = self.create_context(actions=[
            NCWithdrawalAction(amount=100, token_uid=HATHOR_TOKEN_UID),
        ])
        self.runner.call_public_method(self.flash_nc_id, 'withdrawal', ctx)

    def test_use_flash_loan_fail(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.flash_nc_id, self.flash_bp_id, ctx)

        ctx = self.create_context()
        self.runner.create_contract(self.use_nc_id, self.use_bp_id, ctx, self.flash_nc_id)

        ctx = self.create_context()
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(self.use_nc_id, 'run', ctx, 100, HATHOR_TOKEN_UID)

    def test_use_flash_loan_success(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.flash_nc_id, self.flash_bp_id, ctx)

        ctx = self.create_context()
        self.runner.create_contract(self.use_nc_id, self.use_bp_id, ctx, self.flash_nc_id)

        # Deposit funds for the flash loan.
        ctx = self.create_context(actions=[
            NCDepositAction(amount=100, token_uid=HATHOR_TOKEN_UID)
        ])
        self.runner.call_public_method(self.flash_nc_id, 'deposit', ctx)

        ctx = self.create_context()
        self.runner.call_public_method(self.use_nc_id, 'run', ctx, 100, HATHOR_TOKEN_UID)

    def test_flash_loan_call_insufficient_funds(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.flash_nc_id, self.flash_bp_id, ctx)

        ctx = self.create_context()
        self.runner.create_contract(self.use_nc_id, self.use_bp_id, ctx, self.flash_nc_id)

        ctx = self.create_context()
        with self.assertRaises(NCInsufficientFunds):
            self.runner.call_public_method(self.flash_nc_id, 'call', ctx, self.use_nc_id, 'nop', 100)

    def test_flash_loan_call_loan_not_paid(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.flash_nc_id, self.flash_bp_id, ctx)

        ctx = self.create_context()
        self.runner.create_contract(self.use_nc_id, self.use_bp_id, ctx, self.flash_nc_id)

        # Deposit funds for the flash loan.
        ctx = self.create_context(actions=[
            NCDepositAction(amount=100, token_uid=HATHOR_TOKEN_UID)
        ])
        self.runner.call_public_method(self.flash_nc_id, 'deposit', ctx)

        ctx = self.create_context()
        with self.assertRaises(LoanNotFullyPaid):
            self.runner.call_public_method(self.flash_nc_id, 'call', ctx, self.use_nc_id, 'nop', 100)

    def test_flash_loan_call_loan_success(self) -> None:
        ctx = self.create_context()
        self.runner.create_contract(self.flash_nc_id, self.flash_bp_id, ctx)

        ctx = self.create_context()
        self.runner.create_contract(self.use_nc_id, self.use_bp_id, ctx, self.flash_nc_id)

        # Deposit funds for the flash loan.
        ctx = self.create_context(actions=[
            NCDepositAction(amount=100, token_uid=HATHOR_TOKEN_UID)
        ])
        self.runner.call_public_method(self.flash_nc_id, 'deposit', ctx)

        ctx = self.create_context()
        self.runner.call_public_method(self.flash_nc_id, 'call', ctx, self.use_nc_id, 'nop_payback', 100)
