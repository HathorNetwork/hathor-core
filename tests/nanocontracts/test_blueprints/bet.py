# Copyright 2023 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Optional, TypeAlias

from hathor import (
    Address,
    Blueprint,
    Context,
    NCAction,
    NCDepositAction,
    NCFail,
    NCWithdrawalAction,
    SignedData,
    Timestamp,
    TokenUid,
    TxOutputScript,
    export,
    public,
    view,
)

Result: TypeAlias = str
Amount: TypeAlias = int


class InvalidToken(NCFail):
    pass


class ResultAlreadySet(NCFail):
    pass


class ResultNotAvailable(NCFail):
    pass


class TooManyActions(NCFail):
    pass


class TooLate(NCFail):
    pass


class InsufficientBalance(NCFail):
    pass


class InvalidOracleSignature(NCFail):
    pass


@export
class Bet(Blueprint):
    """Bet blueprint with final result provided by an oracle.

    The life cycle of contracts using this blueprint is the following:

    1. [Owner ] Create a contract.
    2. [User 1] `bet(...)` on result A.
    3. [User 2] `bet(...)` on result A.
    4. [User 3] `bet(...)` on result B.
    5. [Oracle] `set_result(...)` as result A.
    6. [User 1] `withdraw(...)`
    7. [User 2] `withdraw(...)`

    Notice that, in the example above, users 1 and 2 won.
    """

    # Total bets per result.
    bets_total: dict[Result, Amount]

    # Total bets per (result, address).
    bets_address: dict[tuple[Result, Address], Amount]

    # Bets grouped by address.
    address_details: dict[Address, dict[Result, Amount]]

    # Amount that has already been withdrawn per address.
    withdrawals: dict[Address, Amount]

    # Total bets.
    total: Amount

    # Final result.
    final_result: Optional[Result]

    # Oracle script to set the final result.
    oracle_script: TxOutputScript

    # Maximum timestamp to make a bet.
    date_last_bet: Timestamp

    # Token for this bet.
    token_uid: TokenUid

    @public
    def initialize(self, ctx: Context, oracle_script: TxOutputScript, token_uid: TokenUid,
                   date_last_bet: Timestamp) -> None:
        if len(ctx.actions) != 0:
            raise NCFail('must be a single call')
        self.bets_total = {}
        self.bets_address = {}
        self.address_details = {}
        self.withdrawals = {}
        self.oracle_script = oracle_script
        self.token_uid = token_uid
        self.date_last_bet = date_last_bet
        self.final_result = None
        self.total = Amount(0)

    @view
    def has_result(self) -> bool:
        """Return True if the final result has already been set."""
        return bool(self.final_result is not None)

    def fail_if_result_is_available(self) -> None:
        """Fail the execution if the final result has already been set."""
        if self.has_result():
            raise ResultAlreadySet

    def fail_if_result_is_not_available(self) -> None:
        """Fail the execution if the final result is not available yet."""
        if not self.has_result():
            raise ResultNotAvailable

    def fail_if_invalid_token(self, action: NCAction) -> None:
        """Fail the execution if the token is invalid."""
        if action.token_uid != self.token_uid:
            token1 = self.token_uid.hex() if self.token_uid else None
            token2 = action.token_uid.hex() if action.token_uid else None
            raise InvalidToken(f'invalid token ({token1} != {token2})')

    def _get_action(self, ctx: Context) -> NCAction:
        """Return the only action available; fails otherwise."""
        if len(ctx.actions) != 1:
            raise TooManyActions('only one token supported')
        if self.token_uid not in ctx.actions:
            raise InvalidToken(f'token different from {self.token_uid.hex()}')
        return ctx.get_single_action(self.token_uid)

    @public(allow_deposit=True)
    def bet(self, ctx: Context, address: Address, score: str) -> None:
        """Make a bet."""
        action = self._get_action(ctx)
        assert isinstance(action, NCDepositAction)
        self.fail_if_result_is_available()
        self.fail_if_invalid_token(action)
        if ctx.block.timestamp > self.date_last_bet:
            raise TooLate(f'cannot place bets after {self.date_last_bet}')
        amount = Amount(action.amount)
        self.total = Amount(self.total + amount)
        if score not in self.bets_total:
            self.bets_total[score] = amount
        else:
            self.bets_total[score] += amount
        key = (score, address)
        if key not in self.bets_address:
            self.bets_address[key] = amount
        else:
            self.bets_address[key] += amount

        # Update dict indexed by address
        if address not in self.address_details:
            self.address_details[address] = {}
        self.address_details[address][score] = self.bets_address[key]

    @public
    def set_result(self, ctx: Context, result: SignedData[Result]) -> None:
        """Set final result. This method is called by the oracle."""
        self.fail_if_result_is_available()
        if not result.checksig(self.syscall.get_contract_id(), self.oracle_script):
            raise InvalidOracleSignature
        self.final_result = result.data

    @public(allow_withdrawal=True)
    def withdraw(self, ctx: Context) -> None:
        """Withdraw tokens after the final result is set."""
        action = self._get_action(ctx)
        assert isinstance(action, NCWithdrawalAction)
        self.fail_if_result_is_not_available()
        self.fail_if_invalid_token(action)
        caller_address = ctx.get_caller_address()
        assert caller_address is not None
        address = Address(caller_address)
        allowed = self.get_max_withdrawal(address)
        if action.amount > allowed:
            raise InsufficientBalance(f'withdrawal amount is greater than available (max: {allowed})')
        if address not in self.withdrawals:
            self.withdrawals[address] = action.amount
        else:
            self.withdrawals[address] += action.amount

    @view
    def get_max_withdrawal(self, address: Address) -> Amount:
        """Return the maximum amount available for withdrawal."""
        total = self.get_winner_amount(address)
        withdrawals = self.withdrawals.get(address, Amount(0))
        return total - withdrawals

    @view
    def get_winner_amount(self, address: Address) -> Amount:
        """Return how much an address has won."""
        self.fail_if_result_is_not_available()
        if self.final_result not in self.bets_total:
            return Amount(0)
        result_total = self.bets_total[self.final_result]
        if result_total == 0:
            return Amount(0)
        address_total = self.bets_address.get((self.final_result, address), 0)
        winner_amount = Amount(address_total * self.total // result_total)
        return winner_amount
