from typing import NamedTuple

from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.types import Context, NCAction, NCActionType, public
from hathor.types import Address, Amount, Timestamp, TokenUid

PRECISION = 10**20


class SwapResult(NamedTuple):
    """Result for an executed swap with the details of the execution.

    Notice that the results are presented for tokens in and tokens out.
    So one must check which one is Token A and which one is Token B."""

    amount_in: Amount
    slippage_in: Amount
    token_in: TokenUid
    amount_out: Amount
    # change_out: Amount
    token_out: TokenUid


def require(condition: bool, errmsg: str) -> None:
    """Helper to fail execution if condition is false."""
    if not condition:
        raise NCFail(errmsg)


class Dozer_Pool(Blueprint):
    """Liquidity pool inspired by Uniswap v2.

    The initial reserves for both Token A and Token B must be deposited at the contract creation.

    The swap methods are:
    - swap_exact_tokens_for_tokens()
    - swap_tokens_for_exact_tokens()

    At all times, we must have the following invariant:
    - `storage.get_balance(token_a) == reserve_a + total_balance_a`
    - `storage.get_balance(token_b) == reserve_b + total_balance_b`

    Features still to be implemented:
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

    user_liquidity: dict[Address, Amount]
    total_liquidity: Amount

    # Balance of users. These are the cashback amounts available for users to withdrawal.
    balance_a: dict[Address, Amount]
    balance_b: dict[Address, Amount]

    # Developer Address
    dev_address: Address

    # Sum of all user balances.
    # total_balance_a = sum(amount for amount in balance_a.items())
    # total_balance_b = sum(amount for amount in balance_b.items())
    total_balance_a: Amount
    total_balance_b: Amount

    # Fee rate to all trades.
    #
    #     fee = (fee_numerator) / (fee_denominator)
    #
    # For example, a fee of 0.3% would be 3/1000.
    fee_numerator: int
    fee_denominator: int

    protocol_fee: Amount

    accumulated_fee: dict[TokenUid, Amount]
    transactions: int
    last_activity_timestamp: Timestamp
    volume_a: Amount
    volume_b: Amount

    @public
    def initialize(
        self,
        ctx: Context,
        token_a: TokenUid,
        token_b: TokenUid,
        fee: Amount,
        protocol_fee: Amount,
    ) -> None:
        """Initialize the liquidity pool for the pair token_a/token_b.

        It expects to receive one deposit of Token A and one of Token B which will form the reserves of the pool.
        """
        if token_a == token_b:
            raise NCFail("token_a cannot be equal to token_b")
        if token_a > token_b:
            raise NCFail("token_a must be smaller than token_b by sort order")

        self.token_a = token_a
        self.token_b = token_b

        self.dev_address = ctx.address

        # LP Fees.
        if fee > 50:
            raise NCFail("fee too high")
        if fee < 0:
            raise NCFail("invalid fee")

        self.fee_numerator = fee
        self.fee_denominator = 1000

        # Protocol Fees. This is a percentage of the fees that goes to the protocol.
        if protocol_fee > 50:
            raise NCFail("protocol fee too high")
        if protocol_fee < 0:
            raise NCFail("invalid protocol fee")

        self.protocol_fee = protocol_fee

        self.accumulated_fee[token_a] = 0
        self.accumulated_fee[token_b] = 0
        self.transactions = 0
        self.volume_a = 0
        self.volume_b = 0
        self.total_balance_a = 0
        self.total_balance_b = 0

        action_a, action_b = self._get_actions_in_in(ctx)
        self.reserve_a = action_a.amount
        self.reserve_b = action_b.amount
        self.total_liquidity = PRECISION * action_a.amount
        self.user_liquidity[ctx.address] = self.total_liquidity

    def get_reserves(self) -> tuple[Amount, Amount]:
        """Return the current reserves."""
        # TODO Add latest_activity_timestamp
        return (self.reserve_a, self.reserve_b)

    def get_k_last(self) -> Amount:
        """Return the last k."""
        return self.reserve_a * self.reserve_b

    def _get_actions_in_in(self, ctx: Context) -> tuple[NCAction, NCAction]:
        """Return token_a and token_b actions. It also validates that both are deposits."""
        action_a, action_b = self._get_actions_a_b(ctx)
        if action_a.type != NCActionType.DEPOSIT:
            raise NCFail("only deposits allowed for token_a")
        if action_b.type != NCActionType.DEPOSIT:
            raise NCFail("only deposits allowed for token_b")
        return action_a, action_b

    def _get_actions_out_out(self, ctx: Context) -> tuple[NCAction, NCAction]:
        """Return token_a and token_b actions. It also validates that both are withdrawals."""
        action_a, action_b = self._get_actions_a_b(ctx)
        if action_a.type != NCActionType.WITHDRAWAL:
            raise NCFail("only withdrawals allowed for token_a")
        if action_b.type != NCActionType.WITHDRAWAL:
            raise NCFail("only withdrawals allowed for token_b")
        return action_a, action_b

    def _get_actions_a_b(self, ctx: Context) -> tuple[NCAction, NCAction]:
        """Return token_a and token_b actions."""
        if set(ctx.actions.keys()) != {self.token_a, self.token_b}:
            raise NCFail("only token_a and token_b are allowed")
        action_a = ctx.actions[self.token_a]
        action_b = ctx.actions[self.token_b]
        self.last_activity_timestamp = ctx.timestamp
        return action_a, action_b

    def _get_actions_in_out(self, ctx: Context) -> tuple[NCAction, NCAction]:
        """Return action_in and action_out, where action_in is a deposit and action_out is a withdrawal."""
        action_a, action_b = self._get_actions_a_b(ctx)

        if action_a.type == NCActionType.DEPOSIT:
            action_in = action_a
            action_out = action_b
        else:
            action_in = action_b
            action_out = action_a

        if action_in.type != NCActionType.DEPOSIT:
            raise NCFail("must have one deposit and one withdrawal")
        if action_out.type != NCActionType.WITHDRAWAL:
            raise NCFail("must have one deposit and one withdrawal")

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
            raise NCFail("should never happen")

    def _get_reserve(self, token_uid: TokenUid) -> Amount:
        if token_uid == self.token_a:
            return self.reserve_a
        elif token_uid == self.token_b:
            return self.reserve_b
        else:
            raise NCFail("should never happen")

    def _update_reserve(self, amount: Amount, token_uid: TokenUid) -> None:
        if token_uid == self.token_a:
            self.reserve_a += amount
        elif token_uid == self.token_b:
            self.reserve_b += amount
        else:
            raise NCFail("should never happen")

    @public
    def change_dev_address(self, ctx: Context, new_address: Address) -> None:
        """Change the dev address"""
        if ctx.address != self.dev_address:
            raise NCFail("only dev can change dev address")
        self.dev_address = new_address

    @public
    def change_protocol_fee(self, ctx: Context, new_fee: int) -> None:
        """Change the protocol fee"""
        if ctx.address != self.dev_address:
            raise NCFail("only dev can change protocol fee")
        if new_fee > 50:
            raise NCFail("protocol fee too high")
        if new_fee < 0:
            raise NCFail("invalid protocol fee")
        self.protocol_fee = new_fee

    @public
    def change_fee(self, ctx: Context, new_fee: int) -> None:
        """Change the fee"""
        if ctx.address != self.dev_address:
            raise NCFail("only dev can change fee")
        if new_fee > 50:
            raise NCFail("fee too high")
        if new_fee < 0:
            raise NCFail("invalid fee")
        self.fee_numerator = new_fee
        self.fee_denominator = 1000

    @public
    def withdraw_cashback(self, ctx: Context) -> None:
        """Withdraw cashback"""
        action_a, action_b = self._get_actions_out_out(ctx)
        if action_a.amount > self.balance_a[ctx.address]:
            raise NCFail("not enough cashback")
        if action_b.amount > self.balance_b[ctx.address]:
            raise NCFail("not enough cashback")
        self.balance_a[ctx.address] -= action_a.amount
        self.balance_b[ctx.address] -= action_b.amount

    def _get_protocol_liquidity_increase(
        self, protocol_fee_amount: Amount, token: TokenUid
    ) -> int:
        """Calculate the liquidity increase equivalent to a defined percentage of the
        collected fee to be minted to the dev address."""
        if token == self.token_a:
            liquidity_increase = int(
                (
                    (self.total_liquidity / PRECISION)
                    * (protocol_fee_amount / 2)
                    / self.reserve_a
                )
                * PRECISION
            )
        else:
            optimal_a = self.quote(protocol_fee_amount, self.reserve_b, self.reserve_a)
            liquidity_increase = int(
                ((self.total_liquidity / PRECISION) * (optimal_a / 2) / self.reserve_a)
                * PRECISION
            )
        return liquidity_increase

    @public
    def swap_exact_tokens_for_tokens(self, ctx: Context) -> SwapResult:
        """Swaps an exact amount of input tokens for as many output tokens as possible."""
        action_in, action_out = self._get_actions_in_out(ctx)
        reserve_in = self._get_reserve(action_in.token_uid)
        reserve_out = self._get_reserve(action_out.token_uid)

        amount_in = action_in.amount
        fee_amount = int(amount_in * self.fee_numerator / self.fee_denominator)
        self.accumulated_fee[action_in.token_uid] += fee_amount
        protocol_fee_amount = int(fee_amount * self.protocol_fee / 100)
        liquidity_increase = self._get_protocol_liquidity_increase(
            protocol_fee_amount, action_in.token_uid
        )
        self.user_liquidity[self.dev_address] = (
            self.user_liquidity.get(self.dev_address, 0) + liquidity_increase
        )
        self.total_liquidity += liquidity_increase
        amount_out = self.get_amount_out(action_in.amount, reserve_in, reserve_out)
        if reserve_out < amount_out:  # type: ignore
            raise NCFail("insufficient funds")
        if action_out.amount > amount_out:
            raise NCFail("amount out is too high")

        slippage_in = amount_out - action_out.amount
        self._update_balance(ctx.address, slippage_in, action_out.token_uid)
        self._update_reserve(amount_in, action_in.token_uid)
        self._update_reserve(-amount_out, action_out.token_uid)
        self.transactions += 1

        if action_in.token_uid == self.token_a:
            self.volume_a += amount_in
        if action_in.token_uid == self.token_b:
            self.volume_b += amount_in

        # Mint Protocol fees for dev address

        return SwapResult(
            action_in.amount,
            slippage_in,
            action_in.token_uid,
            amount_out,
            action_out.token_uid,
        )

    @public
    def swap_tokens_for_exact_tokens(self, ctx: Context) -> SwapResult:
        """Receive an exact amount of output tokens for as few input tokens as possible."""
        action_in, action_out = self._get_actions_in_out(ctx)
        reserve_in = self._get_reserve(action_in.token_uid)
        reserve_out = self._get_reserve(action_out.token_uid)

        amount_out = action_out.amount
        if reserve_out < amount_out:
            raise NCFail("insufficient funds")

        amount_in = self.get_amount_in(action_out.amount, reserve_in, reserve_out)
        fee_amount = int(amount_in * self.fee_numerator / self.fee_denominator)
        self.accumulated_fee[action_in.token_uid] += fee_amount
        protocol_fee_amount = int(fee_amount * self.protocol_fee / 100)
        liquidity_increase = self._get_protocol_liquidity_increase(
            protocol_fee_amount, action_in.token_uid
        )
        self.user_liquidity[self.dev_address] = (
            self.user_liquidity.get(self.dev_address, 0) + liquidity_increase
        )
        self.total_liquidity += liquidity_increase
        if action_in.amount < amount_in:
            raise NCFail("amount in is too low")

        slippage_in = action_in.amount - amount_in
        self._update_balance(ctx.address, slippage_in, action_in.token_uid)
        self._update_reserve(amount_in, action_in.token_uid)
        self._update_reserve(-amount_out, action_out.token_uid)
        self.transactions += 1

        if action_in.token_uid == self.token_a:
            self.volume_a += amount_in
        if action_in.token_uid == self.token_b:
            self.volume_b += amount_in

        return SwapResult(
            action_in.amount,
            slippage_in,
            action_in.token_uid,
            amount_out,
            action_out.token_uid,
        )

    def balance_of(self, owner: Address) -> tuple[Amount, Amount]:
        """Get owner's balance."""
        return (self.balance_a.get(owner, 0), self.balance_b.get(owner, 0))

    def liquidity_of(self, owner: Address) -> float:
        """Get owner's balance."""
        return self.user_liquidity.get(owner, 0)

    def accumulated_fee_of(self, token_uid: TokenUid) -> Amount:
        """Get accumulated fee of a token."""
        return self.accumulated_fee.get(token_uid, 0)

    def get_amount_out(
        self, amount_in: Amount, reserve_in: Amount, reserve_out: Amount
    ) -> Amount:
        """Return the maximum amount_out for an exact amount_in."""
        a = self.fee_denominator - self.fee_numerator
        b = self.fee_denominator
        amount_out = (reserve_out * amount_in * a) // (reserve_in * b + amount_in * a)
        if amount_out > reserve_out:
            amount_out = reserve_out**0.99
        return amount_out

    def get_amount_in(
        self, amount_out: Amount, reserve_in: Amount, reserve_out: Amount
    ) -> Amount:
        """Return the minimum amount_in for an exact amount_out."""
        a = self.fee_denominator - self.fee_numerator
        b = self.fee_denominator
        if amount_out >= reserve_out:
            amount_in = self.quote(amount_out, reserve_out, reserve_in)
        else:
            amount_in = (reserve_in * amount_out * b) // (
                (reserve_out - amount_out) * a
            )
        return amount_in

    def quote(self, amount_a: Amount, reserve_a: Amount, reserve_b: Amount) -> Amount:
        """Return amount_b such that amount_b/amount_a = reserve_b/reserve_a = k"""
        amount_b = (amount_a * reserve_b) // reserve_a
        return amount_b

    @public
    def add_liquidity(
        self,
        ctx: Context,
        # amount_a_min: Amount, amount_b_min: Amount
    ) -> None:
        """Add liquidity to the pool."""
        action_a, action_b = self._get_actions_in_in(ctx)

        optimal_b = self.quote(action_a.amount, self.reserve_a, self.reserve_b)
        if optimal_b <= action_b.amount:
            # require(optimal_b >= amount_b_min, "insufficient b amount")

            change = action_b.amount - optimal_b
            self._update_balance(ctx.address, change, self.token_b)
            liquidity_increase = (
                (self.total_liquidity / PRECISION) * action_a.amount / self.reserve_a
            )
            self.user_liquidity[ctx.address] = self.user_liquidity.get(
                ctx.address, 0
            ) + int(PRECISION * liquidity_increase)
            self.total_liquidity += int(PRECISION * liquidity_increase)
            self.reserve_a += action_a.amount
            self.reserve_b += optimal_b

        else:
            optimal_a = self.quote(action_b.amount, self.reserve_b, self.reserve_a)
            assert optimal_a <= action_a.amount
            # require(optimal_a >= amount_a_min, "insufficient a amount")

            change = action_a.amount - optimal_a
            self._update_balance(ctx.address, change, self.token_a)
            liquidity_increase = (
                (self.total_liquidity / PRECISION) * optimal_a / self.reserve_a
            )
            self.user_liquidity[ctx.address] = self.user_liquidity.get(
                ctx.address, 0
            ) + int(PRECISION * liquidity_increase)
            self.total_liquidity += int(PRECISION * liquidity_increase)
            self.reserve_a += optimal_a
            self.reserve_b += action_b.amount

    @public
    def remove_liquidity(self, ctx: Context):
        """Remove liquidity from the pool."""
        action_a, action_b = self._get_actions_out_out(ctx)
        if self.user_liquidity[ctx.address] == 0:
            raise NCFail("no liquidity to remove")
        max_withdraw = int(
            (self.user_liquidity[ctx.address] / PRECISION)
            * self.reserve_a
            / (self.total_liquidity / PRECISION)
        )
        if max_withdraw < action_a.amount:
            raise NCFail(f"insufficient liquidity: {max_withdraw} < {action_a.amount}")
        optimal_b = self.quote(action_a.amount, self.reserve_a, self.reserve_b)
        if optimal_b < action_b.amount:
            raise NCFail("insufficient b amount")
        change = optimal_b - action_b.amount
        self._update_balance(ctx.address, change, self.token_b)
        liquidity_decrease = (
            (self.total_liquidity / PRECISION) * action_a.amount / self.reserve_a
        )
        self.user_liquidity[ctx.address] = self.user_liquidity.get(
            ctx.address, 0
        ) - int(PRECISION * liquidity_decrease)
        self.total_liquidity -= int(PRECISION * liquidity_decrease)
        # makes sense change total liquidity after removing user liquidity?
        self.reserve_a -= action_a.amount
        self.reserve_b -= optimal_b

    def front_end_api_pool(
        self,
    ) -> dict[str, float]:
        """
        Retrieves the current state of the pool including reserves, fees, volume, and transactions.

        Returns:
            dict[str, float]: A dictionary containing the following keys:
                - reserve0 (float): The current reserve for token A.
                - reserve1 (float): The current reserve for token B.
                - fee (float): The fee denominator for transactions within the pool.
                - volume (float): The total volume of transactions within the pool.
                - fee0 (float): The accumulated fee for token A.
                - fee1 (float): The accumulated fee for token B.
                - slippage0 (float): The accumulated slippage for token A.
                - slippage1 (float): The accumulated slippage for token B.
                - dzr_rewards (float): The fixed reward amount for some operations (1000 as a placeholder).
                - transactions (float): The total number of transactions within the pool.
        """
        return {
            "reserve0": self.reserve_a,
            "reserve1": self.reserve_b,
            "fee": self.fee_numerator / self.fee_denominator,
            "volume": self.volume_a,
            "fee0": self.accumulated_fee[self.token_a],
            "fee1": self.accumulated_fee[self.token_b],
            # "slippage0": self.balance_a,
            # "slippage1": self.balance_b,
            "dzr_rewards": 1000,
            "transactions": self.transactions,
        }

    def front_quote_add_liquidity_in(
        self, amount_in: Amount, token_in: TokenUid
    ) -> float:
        """
        Calculate the amount of other tokens to include for a given input amount in add liquidity event.

        Parameters:
        - amount_in (Amount): The amount of input tokens.
        - token_in (TokenUid): The token to be used as input.

        Returns:
        - Amount: The calculated amount of other tokens to include.
        """
        if token_in == self.token_a:
            quote = self.quote(amount_in, self.reserve_a, self.reserve_b)
        else:
            quote = self.quote(amount_in, self.reserve_b, self.reserve_a)
        return quote

    def front_quote_add_liquidity_out(
        self, amount_out: Amount, token_in: TokenUid
    ) -> float:
        """
        Calculate the amount of other tokens to include for a given output amount in add liquidity event.

        Parameters:
        - amount_out (Amount): The amount of output tokens.
        - token_in (TokenUid): The token to be used as input.

        Returns:
        - Amount: The calculated amount of other tokens to include.
        """
        if token_in == self.token_a:
            quote = self.quote(amount_out, self.reserve_b, self.reserve_a)
        else:
            quote = self.quote(amount_out, self.reserve_a, self.reserve_b)
        return quote

    def front_quote_exact_tokens_for_tokens(
        self, amount_in: Amount, token_in: TokenUid
    ) -> dict[str, float]:
        """
        Calculate the amount of tokens received for a given input amount.

        This method provides a quote for the exact amount of tokens one would receive
        for a specified amount of input tokens, based on the current reserves.

        Parameters:
        - amount_in (Amount): The amount of input tokens.

        Returns:
        - Amount: The calculated amount of tokens that would be received.
        """
        if token_in == self.token_a:
            amount_out = self.get_amount_out(amount_in, self.reserve_a, self.reserve_b)
            quote = self.quote(amount_in, self.reserve_a, self.reserve_b)
        else:
            amount_out = self.get_amount_out(amount_in, self.reserve_b, self.reserve_a)
            quote = self.quote(amount_in, self.reserve_b, self.reserve_a)
        if amount_out == 0:
            price_impact = 0
        else:
            price_impact = (
                100 * (quote - amount_out) / amount_out - self.fee_numerator / 10
            )
        if price_impact < 0:
            price_impact = 0
        return {"amount_out": amount_out, "price_impact": price_impact}

    def front_quote_tokens_for_exact_tokens(
        self, amount_out: Amount, token_in: TokenUid
    ) -> dict[str, float]:
        """
        Calculate the required amount of input tokens to obtain a specific amount of output tokens.

        This method uses the reserves of two tokens (A and B) to determine how much of token A is needed
        to receive a specific amount of token B.

        Parameters:
        - amount_out (Amount): The desired amount of output tokens.

        Returns:
        - Amount: The required amount of input tokens to achieve the desired output.
        """
        # amount_in = self.get_amount_in(amount_out, self.reserve_a, self.reserve_b)
        # quote = self.quote(amount_out, self.reserve_a, self.reserve_b)
        if token_in == self.token_a:
            amount_in = self.get_amount_in(amount_out, self.reserve_a, self.reserve_b)
            quote = self.quote(amount_in, self.reserve_a, self.reserve_b)
        else:
            amount_in = self.get_amount_in(amount_out, self.reserve_b, self.reserve_a)
            quote = self.quote(amount_in, self.reserve_b, self.reserve_a)

        price_impact = 100 * (quote - amount_out) / amount_out - self.fee_numerator / 10
        if price_impact < 0:
            price_impact = 0
        if price_impact >= 100:
            price_impact = 100
        return {"amount_in": amount_in, "price_impact": price_impact}

    def pool_info(
        self,
    ) -> dict[str, str]:

        return {
            # "name": self.name,
            "version": "0.1",
            # "owner": self.owner.hex(),
            # "fee_to": self.fee_to.hex(),
            "token0": self.token_a.hex(),
            "token1": self.token_b.hex(),
            "fee": str(self.fee_numerator / 10),
        }

    def user_info(
        self,
        address: Address,
    ) -> dict[str, float]:
        max_withdraw_a = int(
            (self.user_liquidity[address] / PRECISION)
            * self.reserve_a
            / (self.total_liquidity / PRECISION)
        )
        max_withdraw_b = self.quote(max_withdraw_a, self.reserve_a, self.reserve_b)
        return {
            "balance_a": self.balance_a.get(address, 0),
            "balance_b": self.balance_b.get(address, 0),
            "liquidity": self.user_liquidity.get(address, 0),
            "max_withdraw_a": max_withdraw_a,
            "max_withdraw_b": max_withdraw_b,
        }

    def pool_data(
        self,
    ) -> dict[str, float]:

        return {
            "total_liquidity": self.total_liquidity,
            "reserve0": self.reserve_a,
            "reserve1": self.reserve_b,
            "fee": self.fee_numerator / 10,
            "volume0": self.volume_a,
            "volume1": self.volume_b,
            "fee0": self.accumulated_fee[self.token_a],
            "fee1": self.accumulated_fee[self.token_b],
            # "slippage0": self.balance_a,
            # "slippage1": self.balance_b,
            "dzr_rewards": 1000,
            "transactions": self.transactions,
            "last_actvity_timestamp": self.last_activity_timestamp,
        }
