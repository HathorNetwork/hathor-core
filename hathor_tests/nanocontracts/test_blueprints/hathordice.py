# Copyright 2025 Hathor Labs
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

from hathor import (
    Address,
    Amount,
    Blueprint,
    CallerId,
    Context,
    NCAction,
    NCActionType,
    NCDepositAction,
    NCFail,
    NCWithdrawalAction,
    TokenUid,
    export,
    public,
    view,
)


@export
class HathorDice(Blueprint):
    token_uid: TokenUid
    max_bet_amount: Amount
    max_multiplier_tenths: int | None
    house_edge_basis_points: int  # in basis points (e.g., 50 points = 0.50%)
    random_bit_length: int

    liquidity_providers: dict[CallerId, int]
    total_liquidity_provided: Amount

    balances: dict[CallerId, int]
    available_tokens: Amount

    @public(allow_deposit=True)
    def initialize(
        self,
        ctx: Context,
        token_uid: TokenUid,
        house_edge_basis_points: int,
        max_bet_amount: Amount,
        max_multiplier_tenths: int | None,
        random_bit_length: int,
    ) -> None:
        if house_edge_basis_points < 0:
            raise NCFail('house edge cannot be negative')
        if house_edge_basis_points >= 10_000:
            raise NCFail('house edge too large')

        if random_bit_length < 16:
            raise NCFail('random bit length too small')
        if random_bit_length > 32:
            raise NCFail('random bit length too large')

        if max_bet_amount <= 0:
            raise NCFail('maximum bet amount must be at least 1')

        if max_multiplier_tenths is not None and max_multiplier_tenths <= 10:
            raise NCFail('maximum multiplier should be greater than 1.0x')

        self.token_uid = token_uid
        self.house_edge_basis_points = house_edge_basis_points
        self.max_bet_amount = max_bet_amount
        self.max_multiplier_tenths = max_multiplier_tenths
        self.random_bit_length = random_bit_length

        self.liquidity_providers = {}
        self.balances = {}
        self.available_tokens = Amount(0)
        self.total_liquidity_provided = Amount(0)

        if len(ctx.actions) > 0:
            self.add_liquidity(ctx)

    @public(allow_deposit=True)
    def add_liquidity(self, ctx: Context) -> int:
        action = self._get_deposit_action(ctx)

        amount = action.amount
        adjusted_amount = self.calculate_adjusted_liquidity(amount)

        if ctx.caller_id not in self.liquidity_providers:
            self.liquidity_providers[ctx.caller_id] = adjusted_amount
        else:
            self.liquidity_providers[ctx.caller_id] += adjusted_amount

        self.total_liquidity_provided += adjusted_amount
        self.available_tokens = Amount(self.available_tokens + amount)

        return adjusted_amount

    @view
    def calculate_adjusted_liquidity(self, amount: Amount) -> int:
        """Calculate adjusted liquidity when ADDING liquidity (floor division)."""
        # x = amount
        # y = adjusted_amount
        # A = self.available_tokens
        # L = self.total_liquidity_provided
        #
        # x = y * (A + x) / (L + y)
        # x * (L + y) = y * (A + x)
        # xL + xy = Ay + xy
        # xL = Ay
        # y = x * L // A
        if self.available_tokens == 0:
            return amount
        return (amount * self.total_liquidity_provided) // self.available_tokens

    @view
    def calculate_adjusted_liquidity_removal(self, amount: Amount) -> int:
        """Calculate adjusted liquidity when REMOVING liquidity (ceiling division for security)."""
        if self.available_tokens == 0:
            return amount
        return self._ceil_div(
            amount * self.total_liquidity_provided,
            self.available_tokens
        )

    @public(allow_withdrawal=True)
    def remove_liquidity(self, ctx: Context) -> int:
        action = self._get_withdrawal_action(ctx)

        allowed_withdrawal = self.calculate_address_maximum_liquidity_removal(ctx.caller_id)
        if action.amount > allowed_withdrawal:
            raise NCFail('too large withdrawal')

        amount = action.amount
        adjusted_amount = self.calculate_adjusted_liquidity_removal(amount)

        self.liquidity_providers[ctx.caller_id] -= adjusted_amount
        self.total_liquidity_provided -= adjusted_amount
        self.available_tokens = Amount(self.available_tokens - amount)

        return adjusted_amount

    @view
    def calculate_maximum_liquidity_removal(self, amount: Amount) -> Amount:
        if self.total_liquidity_provided == 0:
            return Amount(0)
        assert amount >= 0
        return Amount((self.available_tokens * amount) // self.total_liquidity_provided)

    @view
    def calculate_address_maximum_liquidity_removal(self, caller_id: CallerId) -> Amount:
        amount = self.liquidity_providers.get(caller_id, 0)
        assert amount >= 0
        return self.calculate_maximum_liquidity_removal(amount)

    @public(allow_deposit=True)
    def place_bet(self, ctx: Context, bet_amount: Amount, threshold: int) -> int:
        if not isinstance(ctx.caller_id, Address):
            raise NCFail('only users are allowed')
        if bet_amount <= 0:
            raise NCFail('bet amount must be positive')
        if bet_amount > self.max_bet_amount:
            raise NCFail('bet amount is too high')

        if threshold <= 0:
            raise NCFail('threshold must be positive')

        max_threshold_numerator = (2**self.random_bit_length) * (10_000 - self.house_edge_basis_points)
        if max_threshold_numerator <= threshold * 10_000:
            raise NCFail('threshold is too large')

        if self.max_multiplier_tenths is not None:
            multiplier_a, multiplier_b = self.calculate_multiplier(threshold)
            if multiplier_a * 10 >= self.max_multiplier_tenths * multiplier_b:
                raise NCFail('multiplier is too large')

        potential_payout = self.calculate_payout(bet_amount, threshold)
        assert potential_payout >= bet_amount, f'{potential_payout} is smaller than {bet_amount}'

        if potential_payout - bet_amount > self.available_tokens:
            raise NCFail('not enough liquidity')

        balance_amount = self.balances.get(ctx.caller_id, 0)

        if len(ctx.actions) > 0:
            action = self._get_deposit_action(ctx)
            deposit_amount = action.amount
        else:
            deposit_amount = 0

        if balance_amount + deposit_amount < bet_amount:
            raise NCFail('not enough balance')

        if deposit_amount < bet_amount:
            # If deposit is not enough to cover the bet amount, get tokens from balance.
            diff = bet_amount - deposit_amount
            assert diff > 0
            self._add_to_balance(ctx.caller_id, -diff)
        elif deposit_amount > bet_amount:
            diff = deposit_amount - bet_amount
            assert diff > 0
            self._add_to_balance(ctx.caller_id, diff)

        lucky_number = self.syscall.rng.randbits(self.random_bit_length)

        if lucky_number >= threshold:
            # Lose it all!
            self.available_tokens = Amount(self.available_tokens + bet_amount)
            self.log.info('you lose', lucky_number=lucky_number)
            self.syscall.emit_event(
                f'{{' \
                f'"bet_amount": {bet_amount},' \
                f'"threshold": {threshold},' \
                f'"lucky_number": {lucky_number},' \
                f'"payout": 0' \
                f'}}'.encode('utf-8')
            )
            return 0

        # Win: Calculate payout with house edge
        payout = potential_payout
        assert payout - bet_amount <= self.available_tokens

        self.available_tokens -= (payout - bet_amount)
        self._add_to_balance(ctx.caller_id, payout)

        self.log.info('you win', lucky_number=lucky_number, payout=payout)
        self.syscall.emit_event(
            f'{{' \
            f'"bet_amount": {bet_amount},' \
            f'"threshold": {threshold},' \
            f'"lucky_number": {lucky_number},' \
            f'"payout": {payout}' \
            f'}}'.encode('utf-8')
        )

        return payout

    def _add_to_balance(self, caller_id: CallerId, diff: int) -> None:
        if caller_id not in self.balances:
            self.balances[caller_id] = diff
        else:
            self.balances[caller_id] += diff

    @public(allow_withdrawal=True)
    def claim_balance(self, ctx: Context) -> None:
        action = self._get_withdrawal_action(ctx)
        if action.amount > self.balances.get(ctx.caller_id, 0):
            raise NCFail('not enough balance')

        self.balances[ctx.caller_id] -= action.amount

    @view
    def get_address_balance(self, caller_id: CallerId) -> Amount:
        return Amount(self.balances.get(caller_id, 0))

    @view
    def calculate_multiplier(self, threshold: int) -> tuple[int, int]:
        # fair_multiplier = 2**32 / threshold
        # adjusted_multipler = fair_multiplier * (1 - house_edge)
        #
        # house_edge = house_edge_basis_points / 100 / 100
        numerator = (2**self.random_bit_length) * (10_000 - self.house_edge_basis_points)
        denominator = 10_000 * threshold
        return (numerator, denominator)

    @view
    def calculate_payout(self, bet_amount: Amount, threshold: int) -> int:
        # payout = bet_amount * adjusted_multiplier
        numerator, denominator = self.calculate_multiplier(threshold)
        return (bet_amount * numerator) // denominator

    def _ceil_div(self, numerator: int, denominator: int) -> int:
        """Calculate ceiling division using (numerator + denominator - 1) // denominator."""
        return (numerator + denominator - 1) // denominator

    def _get_action(self, ctx: Context) -> NCAction:
        if len(ctx.actions) != 1:
            raise NCFail('only one token is allowed')
        return ctx.get_single_action(self.token_uid)

    def _get_withdrawal_action(self, ctx: Context) -> NCWithdrawalAction:
        action = self._get_action(ctx)
        assert isinstance(action, NCWithdrawalAction)
        return action

    def _get_deposit_action(self, ctx: Context) -> NCDepositAction:
        action = self._get_action(ctx)
        assert isinstance(action, NCDepositAction)
        return action
