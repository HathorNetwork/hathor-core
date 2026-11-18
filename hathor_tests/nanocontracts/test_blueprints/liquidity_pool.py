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

from typing import NamedTuple

from hathor import (
    Address,
    Amount,
    Blueprint,
    Context,
    NCAction,
    NCDepositAction,
    NCWithdrawalAction,
    NCFail,
    TokenUid,
    TxOutputScript,
    public,
    view,
)


class SwapResult(NamedTuple):
    """Result for an executed swap with the details of the execution.

    Notice that the results are presented for tokens in and tokens out.
    So one must check which one is Token A and which one is Token B."""
    amount_in: Amount
    change_in: Amount
    token_in: TokenUid
    amount_out: Amount
    change_out: Amount
    token_out: TokenUid
    fee: Amount


def require(condition: bool, errtype: NCFail, errmsg: str) -> None:
    """Helper to fail execution if condition is false."""
    if not condition:
        raise errtype(errmsg)


class LiquidityPool(Blueprint):
    """Liquidity pool inspired by Uniswap v2.

    The initial reserves for both Token A and Token B must be deposited at the contract creation.

    The swap methods are:
    - swap_exact_tokens_for_tokens()
    - swap_tokens_for_exact_tokens()

    At all times, we must have the following invariant:
    - `storage.get_balance(token_a) == reserve_a + total_balance_a`
    - `storage.get_balance(token_b) == reserve_b + total_balance_b`

    Features still to be implemented:
    - User balance withdrawals
    - Fees
    - Events

    Note: Multiple swaps can be executed through multiple calls.
          For instance, one wants to trade A/C. There is no A/C pool available but there are the A/B and B/C pools.
          Then one can trade A/C calling swap@A/B followed by swap@B/C in a single transaction.

    Features that are available in Uniswap v2 but are not implemented here:
    - Oracle
    - Allowance
    - Permit

    Fields to be discussed:
    - name: str
    - symbol: str
    - decimals: int
    - owner: TxOutputScript
    - fee_to: Address
    - fee_to_setter: TxOutputScript
    """

    # Token information for the pair TokenA/TokenB.
    token_a: TokenUid
    token_b: TokenUid

    # Amount of tokens available for the pool.
    #
    # Notice that reserves are different than the contract balance because the balance is
    # the number of tokens controlled by the contract while the reserves keep the amount
    # available for swaps.
    reserve_a: Amount
    reserve_b: Amount

    # Balance of users. These are the amounts available for users to withdrawal.
    balance_a: dict[Address, Amount]
    balance_b: dict[Address, Amount]

    # Sum of all user balances.
    # total_balance_a = sum(amount for amount in balance_a.items())
    # total_balance_b = sum(amount for amount in balance_b.items())
    total_balance_a: Amount
    total_balance_b: Amount

    # LP Token (not implemented yet)
    lp_token: TokenUid

    # Fee rate to all trades.
    #
    #     fee = (fee_numerator) / (fee_denominator)
    #
    # For example, a fee of 0.3% would be 3/1000.
    fee_numerator: int
    fee_denominator: int

    @public(allow_deposit=True)
    def initialize(self,
                   ctx: Context,
                   token_a: TokenUid,
                   token_b: TokenUid,
                   lp_token: TokenUid,
                   fee: Amount) -> None:
        """Initialize the liquidity pool for the pair token_a/token_b.

        It expects to receive one deposit of Token A and one of Token B which will form the reserves of the pool.
        """
        if token_a == token_b:
            raise NCFail('token_a cannot be equal to token_b')
        if token_a > token_b:
            raise NCFail('token_a must be smaller than token_b by sort order')

        # Fee.
        self.fee_numerator = fee
        self.fee_denominator = 10000
        if self.fee_numerator < 0:
            raise NCFail('negative fee')
        if self.fee_numerator > self.fee_denominator:
            raise NCFail('invalid fee')

        self.token_a = token_a
        self.token_b = token_b
        self.lp_token = lp_token

        self.balance_a = {}
        self.balance_b = {}

        self.total_balance_a = 0
        self.total_balance_b = 0

        action_a, action_b = self._get_actions_in_in(ctx)
        self.reserve_a = action_a.amount
        self.reserve_b = action_b.amount

    @view
    def get_reserves(self) -> tuple[Amount, Amount]:
        """Return the current reserves."""
        # TODO Add latest_activity_timestamp
        return (self.reserve_a, self.reserve_b)

    @view
    def get_k_last(self) -> Amount:
        """Return the last k."""
        return self.reserve_a * self.reserve_b

    def _get_actions_in_in(self, ctx: Context) -> tuple[NCAction, NCAction]:
        """Return token_a and token_b actions. It also validates that both are deposits."""
        action_a, action_b = self._get_actions_a_b(ctx)
        if not isinstance(action_a, NCDepositAction):
            raise NCFail(f'only deposits allowed for token_a {action_a}')
        if not isinstance(action_b, NCDepositAction):
            raise NCFail(f'only deposits allowed for token_b {action_b}')
        return action_a, action_b

    def _get_actions_a_b(self, ctx: Context) -> tuple[NCAction, NCAction]:
        """Return token_a and token_b actions."""
        if set(ctx.actions.keys()) != {self.token_a, self.token_b}:
            raise NCFail('only token_a and token_b are allowed')
        action_a = ctx.get_single_action(self.token_a)
        action_b = ctx.get_single_action(self.token_b)
        return action_a, action_b

    def _get_actions_in_out(self, ctx: Context) -> tuple[NCAction, NCAction]:
        """Return action_in and action_out, where action_in is a deposit and action_out is a withdrawal."""
        action_a, action_b = self._get_actions_a_b(ctx)

        if isinstance(action_a, NCDepositAction):
            action_in = action_a
            action_out = action_b
        else:
            action_in = action_b
            action_out = action_a

        if not isinstance(action_in, NCDepositAction):
            raise NCFail('must have one deposit and one withdrawal')
        if not isinstance(action_out, NCWithdrawalAction):
            raise NCFail('must have one deposit and one withdrawal')

        return action_in, action_out

    def _update_balance(self, to: Address, amount: Amount, token: TokenUid) -> None:
        """Update balance for a given change."""
        if amount == 0:
            return

        if token == self.token_a:
            self.balance_a[to] = self.balance_a.get(to, 0) + amount
            self.total_balance_a += amount
        elif token == self.token_b:
            self.balance_b[to] = self.balance_b.get(to, 0) + amount
            self.total_balance_b += amount
        else:
            raise NCFail('should never happen')

    def _get_reserve(self, token_uid: TokenUid) -> None:
        if token_uid == self.token_a:
            return self.reserve_a
        elif token_uid == self.token_b:
            return self.reserve_b
        else:
            raise NCFail('should never happen')

    def _update_reserve(self, amount, token_uid) -> None:
        if token_uid == self.token_a:
            self.reserve_a += amount
        elif token_uid == self.token_b:
            self.reserve_b += amount
        else:
            raise NCFail('should never happen')

    @public(allow_deposit=True, allow_withdrawal=True)
    def swap_exact_tokens_for_tokens(self, ctx: Context, to: Address) -> SwapResult:
        """Swaps an exact amount of input tokens for as many output tokens as possible."""
        action_in, action_out = self._get_actions_in_out(ctx)
        reserve_in = self._get_reserve(action_in.token_uid)
        reserve_out = self._get_reserve(action_out.token_uid)

        amount_in = action_in.amount
        amount_out = self._get_amount_out(action_in.amount, reserve_in, reserve_out)
        if reserve_out < amount_out:
            raise NCFail('insufficient funds')
        if action_out.amount > amount_out:
            raise NCFail('amount out is too high')

        amount_out_no_fees = self._get_amount_out(action_in.amount, reserve_in, reserve_out, skip_fee=True)
        fee = amount_out_no_fees - amount_out

        change_out = amount_out - action_out.amount
        self._update_balance(to, change_out, action_out.token_uid)
        self._update_reserve(amount_in, action_in.token_uid)
        self._update_reserve(-amount_out, action_out.token_uid)

        return SwapResult(action_in.amount, 0, action_in.token_uid, amount_out, change_out, action_out.token_uid, fee=fee)

    @public(allow_deposit=True, allow_withdrawal=True)
    def swap_tokens_for_exact_tokens(self, ctx: Context, to: Address) -> SwapResult:
        """Receive an exact amount of output tokens for as few input tokens as possible."""
        action_in, action_out = self._get_actions_in_out(ctx)
        reserve_in = self._get_reserve(action_in.token_uid)
        reserve_out = self._get_reserve(action_out.token_uid)

        amount_out = action_out.amount
        if reserve_out < amount_out:
            raise NCFail('insufficient funds')

        amount_in = self._get_amount_in(action_out.amount, reserve_in, reserve_out)
        if action_in.amount < amount_in:
            raise NCFail('amount in is too low')

        amount_in_no_fees = self._get_amount_in(action_out.amount, reserve_in, reserve_out, skip_fee=True)
        fee = amount_in_no_fees - amount_in

        change_in = action_in.amount - amount_in
        self._update_balance(to, change_in, action_in.token_uid)
        self._update_reserve(amount_in, action_in.token_uid)
        self._update_reserve(-amount_out, action_out.token_uid)

        return SwapResult(amount_in, change_in, action_in.token_uid, action_out.amount, 0, action_out.token_uid, fee=fee)

    @view
    def balance_of(self, owner: Address) -> tuple[Amount, Amount]:
        """Get owner's balance."""
        return (self.balance_a.get(owner, 0), self.balance_b.get(owner, 0))

    @view
    def get_amount_out(self, amount_in: Amount, reserve_in: Amount, reserve_out: Amount) -> Amount:
        return self._get_amount_out(amount_in, reserve_in, reserve_out)

    def _get_amount_out(self, amount_in: Amount, reserve_in: Amount, reserve_out: Amount, *, skip_fee: bool = False) -> Amount:
        """Return the maximum amount_out for an exact amount_in."""
        if not skip_fee:
            a = self.fee_denominator - self.fee_numerator
            b = self.fee_denominator
        else:
            a = 1
            b = 1
        amount_out = (reserve_out * amount_in * a) // ((reserve_in + amount_in) * b)
        return amount_out

    @view
    def get_amount_in(self, amount_out: Amount, reserve_in: Amount, reserve_out: Amount) -> Amount:
        return self._get_amount_in(amount_out, reserve_in, reserve_out)

    def _get_amount_in(self, amount_out: Amount, reserve_in: Amount, reserve_out: Amount, *, skip_fee: bool = False) -> Amount:
        """Return the minimum amount_in for an exact amount_out."""
        if not skip_fee:
            a = self.fee_denominator - self.fee_numerator
            b = self.fee_denominator
        else:
            a = 1
            b = 1
        amount_in = (reserve_in * amount_out * b) // ((reserve_out - amount_out) * a)
        return amount_in

    @view
    def quote(self, amount_a: Amount, reserve_a: Amount, reserve_b: Amount) -> Amount:
        """Return amount_b such that amount_b/amount_a = reserve_b/reserve_a = k"""
        amount_b = (amount_a * reserve_b) // reserve_a
        return amount_b

    @public(allow_deposit=True)
    def add_liquidity(self,
                      ctx: Context,
                      amount_a_min: Amount,
                      amount_b_min: Amount,
                      to: Address) -> None:
        """Add liquidity to the pool."""
        action_a, action_b = self._get_actions_in_in(ctx)

        optimal_b = self.quote(action_a.amount, self.reserve_a, self.reserve_b)
        if optimal_b <= action_b.amount:
            require(optimal_b >= amount_b_min, NCFail, 'insufficient b amount')

            change = action_b.amount - optimal_b
            self._update_balance(to, change, self.token_b)

            self.reserve_a += action_a.amount
            self.reserve_b += optimal_b

        else:
            optimal_a = self.quote(action_b.amount, self.reserve_b, self.reserve_a)
            assert optimal_a <= action_a.amount
            require(optimal_a >= amount_a_min, NCFail, 'insufficient a amount')

            change = action_a.amount - optimal_a
            self._update_balance(to, change, self.token_a)

            self.reserve_a += optimal_a
            self.reserve_b += action_b.amount

    @public(allow_deposit=True, allow_withdrawal=True)
    def remove_liquidity(self,
                         ctx: Context,
                         amount_a_min: Amount,
                         amount_b_min: Amount,
                         to: Address) -> None:
        """Remove liquidity from the pool."""
        raise NCFail('not implemented yet')

    @public
    def set_owner(self, ctx: Context, owner: TxOutputScript) -> None:
        if len(ctx.actions) != 0:
            raise NCFail('must be a single call')
        self.owner = owner

    @public
    def mint(self, ctx: Context, to: Address) -> None:
        pass

    @public
    def burn(self, ctx: Context, to: Address) -> None:
        pass

    @public
    def skim(self, ctx: Context, to: Address) -> None:
        pass

    @public
    def sync(self, ctx: Context) -> None:
        pass
