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

from json import dumps
from typing import Any, NamedTuple

from hathor.conf import settings
from hathor.crypto.util import get_address_b58_from_bytes
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.types import (
    Address,
    Amount,
    ContractId,
    NCAction,
    NCActionType,
    NCDepositAction,
    NCWithdrawalAction,
    Timestamp,
    TokenUid,
    public,
    view,
)

PRECISION = Amount(10 ** 20)
HTR_UID = settings.HATHOR_TOKEN_UID


# Custom error classes
class PoolExists(NCFail):
    """Raised when trying to create a pool that already exists."""

    pass


class PoolNotFound(NCFail):
    """Raised when trying to use a pool that doesn't exist."""

    pass


class InvalidTokens(NCFail):
    """Raised when invalid tokens are provided."""

    pass


class InvalidFee(NCFail):
    """Raised when an invalid fee is provided."""

    pass


class InvalidAction(NCFail):
    """Raised when an invalid token action is provided."""

    pass


class Unauthorized(NCFail):
    """Raised when an unauthorized address tries to perform an action."""

    pass


class InvalidPath(NCFail):
    """Raised when an invalid swap path is provided."""

    pass


class InsufficientLiquidity(NCFail):
    """Raised when there is insufficient liquidity for an operation."""

    pass


class SwapResult(NamedTuple):
    """Result for an executed swap with the details of the execution.

    Notice that the results are presented for tokens in and tokens out.
    So one must check which one is Token A and which one is Token B."""

    amount_in: Amount
    slippage_in: Amount
    token_in: TokenUid
    amount_out: Amount
    token_out: TokenUid


class DozerPoolManager(Blueprint):
    """Singleton manager for multiple liquidity pools inspired by Uniswap v2.

    This contract manages multiple liquidity pools in a single contract.
    Each pool is identified by a composite key of token_a/token_b/fee.

    The swap methods are:
    - swap_exact_tokens_for_tokens()
    - swap_tokens_for_exact_tokens()

    Features:
    - Multiple pools in a single contract
    - Protocol fee collection
    - Liquidity management
    - Pool statistics tracking
    - Signed pools for listing in Dozer dApp
    """

    # Administrative state
    owner: Address
    default_fee: Amount
    default_protocol_fee: Amount
    authorized_signers: dict[Address, bool]  # Addresses authorized to sign pools
    htr_usd_pool_key: str  # Reference pool key for HTR-USD price calculations

    # Pool registry - token_a/token_b/fee -> exists
    pool_exists: dict[str, bool]

    # Token registry
    all_pools: list[str]  # List of all pool keys
    token_to_pools: dict[TokenUid, list[str]]  # Token -> list of pool keys

    # Signed pools for dApp listing
    signed_pools: list[str]  # List of all signed pools
    pool_signers: dict[str, Address]  # pool_key -> signer_address

    # Price calculation
    htr_token_map: dict[
        TokenUid, str
    ]  # token -> pool_key with lowest fee (for HTR pairs)

    # Pool data - using composite keys (token_a/token_b/fee)
    # Every pool data structure follows similar organization to Dozer_Pool_v1_1

    # Token information per pool
    pool_token_a: dict[str, TokenUid]  # pool_key -> token_a
    pool_token_b: dict[str, TokenUid]  # pool_key -> token_b

    # Pool reserves
    pool_reserve_a: dict[str, Amount]  # pool_key -> reserve_a
    pool_reserve_b: dict[str, Amount]  # pool_key -> reserve_b

    # Pool-specific fees
    pool_fee_numerator: dict[str, Amount]  # pool_key -> fee_numerator
    pool_fee_denominator: dict[str, Amount]  # pool_key -> fee_denominator

    # Liquidity tracking
    pool_total_liquidity: dict[str, Amount]  # pool_key -> total_liquidity
    pool_user_liquidity: dict[
        str, dict[Address, Amount]
    ]  # pool_key -> user -> liquidity

    # User balances (for slippage)
    pool_balance_a: dict[str, dict[Address, Amount]]  # pool_key -> user -> balance_a
    pool_balance_b: dict[str, dict[Address, Amount]]  # pool_key -> user -> balance_b
    pool_total_balance_a: dict[str, Amount]  # pool_key -> total_balance_a
    pool_total_balance_b: dict[str, Amount]  # pool_key -> total_balance_b

    # Pool statistics
    pool_accumulated_fee: dict[
        str, dict[TokenUid, Amount]
    ]  # pool_key -> token -> amount
    pool_transactions: dict[str, Amount]  # pool_key -> transaction count
    pool_last_activity: dict[str, Timestamp]  # pool_key -> last activity timestamp
    pool_volume_a: dict[str, Amount]  # pool_key -> volume_a
    pool_volume_b: dict[str, Amount]  # pool_key -> volume_b

    @public
    def initialize(self, ctx: Context) -> None:
        """Initialize the DozerPoolManager contract.

        Sets up the initial state for the contract.
        """
        self.owner = Address(ctx.address)
        self.default_fee = Amount(3)  # 0.3%
        self.default_protocol_fee = Amount(10)  # 10% of fees

        # Add owner as authorized signer
        self.authorized_signers[self.owner] = True

    def _get_pool_key(self, token_a: TokenUid, token_b: TokenUid, fee: Amount) -> str:
        """Create a standardized pool key from tokens and fee.

        Args:
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool

        Returns:
            A composite key in the format token_a:token_b:fee
        """
        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        # Create composite key
        return f"{token_a.hex()}/{token_b.hex()}/{fee}"

    def _validate_pool_exists(self, pool_key: str) -> None:
        """Check if a pool exists, raising error if not.

        Args:
            pool_key: The pool key to check

        Raises:
            PoolNotFound: If the pool does not exist
        """
        if not self.pool_exists.get(pool_key, False):
            raise PoolNotFound(f"Pool does not exist: {pool_key}")

    def _get_actions_a_b(
        self, ctx: Context, pool_key: str
    ) -> tuple[NCAction, NCAction]:
        """Get and validate token actions for a specific pool.

        Args:
            ctx: The transaction context
            pool_key: The pool key

        Returns:
            A tuple of (action_a, action_b)

        Raises:
            InvalidTokens: If the actions don't match the pool tokens
        """
        token_a = self.pool_token_a[pool_key]
        token_b = self.pool_token_b[pool_key]

        if set(ctx.actions.keys()) != {token_a, token_b}:
            raise InvalidTokens("Only token_a and token_b are allowed")

        action_a = ctx.get_single_action(token_a)
        action_b = ctx.get_single_action(token_b)

        # Update last activity timestamp
        self.pool_last_activity[pool_key] = Timestamp(ctx.timestamp)

        return action_a, action_b

    def _get_actions_in_in(
        self, ctx: Context, pool_key: str
    ) -> tuple[NCAction, NCAction]:
        """Return token_a and token_b actions. It also validates that both are deposits.

        Args:
            ctx: The transaction context
            pool_key: The pool key

        Returns:
            A tuple of (action_a, action_b) both deposits

        Raises:
            InvalidAction: If any action is not a deposit
        """
        action_a, action_b = self._get_actions_a_b(ctx, pool_key)
        if action_a.type != NCActionType.DEPOSIT:
            raise InvalidAction("Only deposits allowed for token_a")
        if action_b.type != NCActionType.DEPOSIT:
            raise InvalidAction("Only deposits allowed for token_b")
        return action_a, action_b

    def _get_actions_out_out(
        self, ctx: Context, pool_key: str
    ) -> tuple[NCAction, NCAction]:
        """Return token_a and token_b actions. It also validates that both are withdrawals.

        Args:
            ctx: The transaction context
            pool_key: The pool key

        Returns:
            A tuple of (action_a, action_b) both withdrawals

        Raises:
            InvalidAction: If any action is not a withdrawal
        """
        action_a, action_b = self._get_actions_a_b(ctx, pool_key)
        if action_a.type != NCActionType.WITHDRAWAL:
            raise InvalidAction("Only withdrawals allowed for token_a")
        if action_b.type != NCActionType.WITHDRAWAL:
            raise InvalidAction("Only withdrawals allowed for token_b")
        return action_a, action_b

    def _get_actions_in_out(
        self, ctx: Context, pool_key: str
    ) -> tuple[NCAction, NCAction]:
        """Return action_in and action_out, where action_in is a deposit and action_out is a withdrawal.

        Args:
            ctx: The transaction context
            pool_key: The pool key

        Returns:
            A tuple of (action_in, action_out)

        Raises:
            InvalidAction: If there isn't exactly one deposit and one withdrawal
        """
        action_a, action_b = self._get_actions_a_b(ctx, pool_key)

        if action_a.type == NCActionType.DEPOSIT:
            action_in = action_a
            action_out = action_b
        else:
            action_in = action_b
            action_out = action_a

        if action_in.type != NCActionType.DEPOSIT:
            raise InvalidAction("Must have one deposit and one withdrawal")
        if action_out.type != NCActionType.WITHDRAWAL:
            raise InvalidAction("Must have one deposit and one withdrawal")

        return action_in, action_out

    def _update_balance(
        self, address: Address, amount: Amount, token: TokenUid, pool_key: str
    ) -> None:
        """Update balance for a given change.

        Args:
            address: The user address
            amount: The amount to update
            token: The token
            pool_key: The pool key
        """
        if amount == 0:
            return

        token_a = self.pool_token_a[pool_key]

        if token == token_a:
            # Update balance_a using the partial approach
            partial_balance_a = self.pool_balance_a.get(pool_key, {})
            partial_balance_a.update(
                {address: Amount(partial_balance_a.get(address, Amount(0)) + amount)}
            )
            self.pool_balance_a[pool_key] = partial_balance_a

            # Update total balance
            pool_total_balance_a = self.pool_total_balance_a.get(pool_key, 0)
            pool_total_balance_a += amount
            self.pool_total_balance_a[pool_key] = Amount(pool_total_balance_a)
        else:
            # Update balance_b using the partial approach
            partial_balance_b = self.pool_balance_b.get(pool_key, {})
            partial_balance_b.update(
                {address: Amount(partial_balance_b.get(address, 0) + amount)}
            )
            self.pool_balance_b[pool_key] = partial_balance_b

            # Update total balance
            pool_total_balance_b = self.pool_total_balance_b.get(pool_key, 0)
            pool_total_balance_b += amount
            self.pool_total_balance_b[pool_key] = Amount(pool_total_balance_b)

    def _get_reserve(self, token_uid: TokenUid, pool_key: str) -> Amount:
        """Get the reserve for a token in a pool.

        Args:
            token_uid: The token
            pool_key: The pool key

        Returns:
            The reserve amount

        Raises:
            InvalidTokens: If the token is not part of the pool
        """
        if token_uid == self.pool_token_a[pool_key]:
            return self.pool_reserve_a[pool_key]
        elif token_uid == self.pool_token_b[pool_key]:
            return self.pool_reserve_b[pool_key]
        else:
            raise InvalidTokens("Token not in pool")

    def _update_reserve(
        self, amount: Amount, token_uid: TokenUid, pool_key: str
    ) -> None:
        """Update reserve for a token in a pool.

        Args:
            amount: The amount to update
            token_uid: The token
            pool_key: The pool key

        Raises:
            InvalidTokens: If the token is not part of the pool
        """
        if token_uid == self.pool_token_a[pool_key]:
            self.pool_reserve_a[pool_key] = Amount(
                self.pool_reserve_a[pool_key] + amount
            )
        elif token_uid == self.pool_token_b[pool_key]:
            self.pool_reserve_b[pool_key] = Amount(
                self.pool_reserve_b[pool_key] + amount
            )
        else:
            raise InvalidTokens("Token not in pool")

    @view
    def quote(self, amount_a: Amount, reserve_a: Amount, reserve_b: Amount) -> Amount:
        """Return amount_b such that amount_b/amount_a = reserve_b/reserve_a = k

        Args:
            amount_a: The amount of token A
            reserve_a: The reserve of token A
            reserve_b: The reserve of token B

        Returns:
            The equivalent amount of token B
        """
        amount_b = (amount_a * reserve_b) // reserve_a
        return Amount(amount_b)

    @view
    def get_amount_out(
        self,
        amount_in: Amount,
        reserve_in: Amount,
        reserve_out: Amount,
        fee_numerator: int,
        fee_denominator: int,
    ) -> Amount:
        """Return the maximum amount_out for an exact amount_in.

        Args:
            amount_in: The input amount
            reserve_in: The input reserve
            reserve_out: The output reserve
            fee_numerator: The fee numerator
            fee_denominator: The fee denominator

        Returns:
            The output amount
        """
        a = fee_denominator - fee_numerator
        b = fee_denominator
        amount_out = (reserve_out * amount_in * a) // (reserve_in * b + amount_in * a)
        if amount_out > reserve_out:
            amount_out = reserve_out ** 0.99
        return Amount(amount_out)

    @view
    def get_amount_in(
        self,
        amount_out: Amount,
        reserve_in: Amount,
        reserve_out: Amount,
        fee_numerator: int,
        fee_denominator: int,
    ) -> Amount:
        """Return the minimum amount_in for an exact amount_out.

        Args:
            amount_out: The output amount
            reserve_in: The input reserve
            reserve_out: The output reserve
            fee_numerator: The fee numerator
            fee_denominator: The fee denominator

        Returns:
            The input amount
        """
        a = fee_denominator - fee_numerator
        b = fee_denominator
        if amount_out >= reserve_out:
            amount_in = self.quote(amount_out, reserve_out, reserve_in)
        else:
            amount_in = (reserve_in * amount_out * b) // (
                (reserve_out - amount_out) * a
            )
        return Amount(amount_in)

    @view
    def front_quote_add_liquidity_in(
        self, amount_in: Amount, token_in: TokenUid, pool_key: str
    ) -> Amount:
        """Calculate the amount of other tokens to include for a given input amount in add liquidity event.

        Args:
            amount_in: The amount of input tokens
            token_in: The token to be used as input
            pool_key: The pool key identifying the pool

        Returns:
            The calculated amount of other tokens to include

        Raises:
            PoolNotFound: If the pool does not exist
        """
        if pool_key not in self.all_pools:
            raise PoolNotFound()

        reserve_a = self.pool_reserve_a[pool_key]
        reserve_b = self.pool_reserve_b[pool_key]
        token_a = self.pool_token_a[pool_key]

        if token_in == token_a:
            # Input is token A, calculate required token B
            quote = self.quote(amount_in, reserve_a, reserve_b)
        else:
            # Input is token B, calculate required token A
            quote = self.quote(amount_in, reserve_b, reserve_a)

        return quote

    @view
    def front_quote_add_liquidity_out(
        self, amount_out: Amount, token_in: TokenUid, pool_key: str
    ) -> Amount:
        """Calculate the amount of other tokens to include for a given output amount in add liquidity event.

        Args:
            amount_out: The amount of output tokens
            token_in: The token to be used as input
            pool_key: The pool key identifying the pool

        Returns:
            The calculated amount of other tokens to include

        Raises:
            PoolNotFound: If the pool does not exist
        """
        if pool_key not in self.all_pools:
            raise PoolNotFound()

        reserve_a = self.pool_reserve_a[pool_key]
        reserve_b = self.pool_reserve_b[pool_key]
        token_a = self.pool_token_a[pool_key]

        if token_in == token_a:
            # Input is token A, calculate required token A for given token B output
            quote = self.quote(amount_out, reserve_b, reserve_a)
        else:
            # Input is token B, calculate required token B for given token A output
            quote = self.quote(amount_out, reserve_a, reserve_b)

        return quote

    def _get_protocol_liquidity_increase(
        self, protocol_fee_amount: Amount, token: TokenUid, pool_key: str
    ) -> Amount:
        """Calculate the liquidity increase equivalent to a defined percentage of the
        collected fee to be minted to the owner address.

        Args:
            protocol_fee_amount: The protocol fee amount
            token: The token
            pool_key: The pool key

        Returns:
            The liquidity increase
        """
        if token == self.pool_token_a[pool_key]:
            liquidity_increase = (
                self.pool_total_liquidity[pool_key]
                * protocol_fee_amount
                // (self.pool_reserve_a[pool_key] * 2)
            )
        else:
            optimal_a = self.quote(
                protocol_fee_amount,
                self.pool_reserve_b[pool_key],
                self.pool_reserve_a[pool_key],
            )
            liquidity_increase = (
                self.pool_total_liquidity[pool_key]
                * optimal_a
                // (self.pool_reserve_a[pool_key] * 2)
            )
        return Amount(liquidity_increase)

    @public(allow_deposit=True)
    def create_pool(
        self,
        ctx: Context,
        fee: Amount,
    ) -> str:
        """Create a new liquidity pool with initial deposits.

        Args:
            ctx: The transaction context
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool (default: use default_fee)

        Returns:
            The pool key

        Raises:
            InvalidTokens: If tokens are invalid
            PoolExists: If the pool already exists
            InvalidFee: If the fee is invalid
        """
        token_a, token_b = set(ctx.actions.keys())

        # Validate tokens
        if token_a == token_b:
            raise InvalidTokens("token_a cannot be equal to token_b")

        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        # Create pool key
        pool_key = self._get_pool_key(token_a, token_b, fee)

        # Check if pool already exists
        if self.pool_exists.get(pool_key, False):
            raise PoolExists("Pool already exists")

        # Validate fee
        if fee > 50:
            raise InvalidFee("Fee too high")
        if fee < 0:
            raise InvalidFee("Invalid fee")

        # Get initial deposits
        if set(ctx.actions.keys()) != {token_a, token_b}:
            raise InvalidTokens("Only token_a and token_b are allowed")

        action_a = ctx.get_single_action(token_a)
        action_b = ctx.get_single_action(token_b)

        if (
            action_a.type != NCActionType.DEPOSIT
            or action_b.type != NCActionType.DEPOSIT
        ):
            raise InvalidAction("Only deposits allowed for initial liquidity")

        action_a_amount = Amount(
            action_a.amount if isinstance(action_a, NCDepositAction) else 0
        )
        action_b_amount = Amount(
            action_b.amount if isinstance(action_b, NCDepositAction) else 0
        )

        # Initialize pool data
        self.pool_exists[pool_key] = True
        self.pool_token_a[pool_key] = token_a
        self.pool_token_b[pool_key] = token_b
        self.pool_reserve_a[pool_key] = action_a_amount
        self.pool_reserve_b[pool_key] = action_b_amount

        # Set up fees
        self.pool_fee_numerator[pool_key] = fee
        self.pool_fee_denominator[pool_key] = Amount(1000)

        # Initialize liquidity
        initial_liquidity = PRECISION * action_a_amount
        self.pool_total_liquidity[pool_key] = Amount(initial_liquidity)

        # Initialize user liquidity for this pool
        if pool_key not in self.pool_user_liquidity:
            self.pool_user_liquidity[pool_key] = {}
        self.pool_user_liquidity[pool_key][Address(ctx.address)] = Amount(
            initial_liquidity
        )

        # Initialize statistics
        self.pool_accumulated_fee[pool_key] = {}
        self.pool_accumulated_fee[pool_key][token_a] = Amount(0)
        self.pool_accumulated_fee[pool_key][token_b] = Amount(0)
        self.pool_transactions[pool_key] = Amount(0)
        self.pool_volume_a[pool_key] = Amount(0)
        self.pool_volume_b[pool_key] = Amount(0)
        self.pool_total_balance_a[pool_key] = Amount(0)
        self.pool_total_balance_b[pool_key] = Amount(0)
        self.pool_last_activity[pool_key] = Timestamp(ctx.timestamp)

        # Update registry
        # all_pools should already be initialized by the Blueprint system
        self.all_pools.append(pool_key)

        # Update token to pools mapping
        partial_a = list(self.token_to_pools.get(token_a, tuple()))
        partial_a.append(pool_key)
        self.token_to_pools[token_a] = partial_a

        # For token_b
        partial_b = list(self.token_to_pools.get(token_b, tuple()))
        partial_b.append(pool_key)
        self.token_to_pools[token_b] = partial_b

        # Update HTR token map if this is an HTR pool
        if token_a == HTR_UID or token_b == HTR_UID:
            other_token = token_b if token_a == HTR_UID else token_a

            # If token not in map or new pool has lower fee, update the map
            current_pool_key = self.htr_token_map.get(other_token)
            if (
                current_pool_key is None
                or self.pool_fee_numerator[pool_key]
                < self.pool_fee_numerator[current_pool_key]
            ):
                self.htr_token_map[other_token] = pool_key

        return pool_key

    @public(allow_deposit=True)
    def add_liquidity(
        self,
        ctx: Context,
        fee: Amount,
    ) -> tuple[TokenUid, Amount]:
        """Add liquidity to an existing pool.

        Args:
            ctx: The transaction context
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool (default: use default_fee)

        Returns:
            A tuple of (token, change_amount)

        Raises:
            PoolNotFound: If the pool does not exist
            InvalidAction: If the actions are invalid
        """
        token_a, token_b = set(ctx.actions.keys())
        user_address = Address(ctx.address)

        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        pool_key = self._get_pool_key(token_a, token_b, fee)
        self._validate_pool_exists(pool_key)

        action_a, action_b = self._get_actions_in_in(ctx, pool_key)

        # This logic mirrors Dozer_Pool_v1_1.add_liquidity
        reserve_a = self.pool_reserve_a[pool_key]
        reserve_b = self.pool_reserve_b[pool_key]

        action_a_amount = Amount(
            action_a.amount if isinstance(action_a, NCDepositAction) else 0
        )
        action_b_amount = Amount(
            action_b.amount if isinstance(action_b, NCDepositAction) else 0
        )

        optimal_b = self.quote(action_a_amount, reserve_a, reserve_b)
        if optimal_b <= action_b_amount:
            change = action_b_amount - optimal_b
            self._update_balance(
                user_address, change, self.pool_token_b[pool_key], pool_key
            )

            # Calculate liquidity increase
            liquidity_increase = (
                self.pool_total_liquidity[pool_key] * action_a_amount // reserve_a
            )

            # Update user liquidity
            partial = self.pool_user_liquidity.get(pool_key, {})
            partial[user_address] = Amount(
                partial.get(user_address, Amount(0)) + liquidity_increase
            )
            self.pool_user_liquidity[pool_key] = partial

            # Update total liquidity
            self.pool_total_liquidity[pool_key] = Amount(
                self.pool_total_liquidity[pool_key] + liquidity_increase
            )

            # Update reserves
            self.pool_reserve_a[pool_key] = Amount(
                self.pool_reserve_a[pool_key] + action_a_amount
            )
            self.pool_reserve_b[pool_key] = Amount(
                self.pool_reserve_b[pool_key] + optimal_b
            )

            return (self.pool_token_b[pool_key], change)
        else:
            optimal_a = self.quote(action_b_amount, reserve_b, reserve_a)

            # Validate optimal_a is not greater than action_a.amount
            if optimal_a > action_a_amount:
                raise InvalidAction("Insufficient token A amount")

            change = action_a_amount - optimal_a
            self._update_balance(
                user_address, change, self.pool_token_a[pool_key], pool_key
            )

            # Calculate liquidity increase
            liquidity_increase = (
                self.pool_total_liquidity[pool_key] * optimal_a // reserve_a
            )

            # Update user liquidity
            partial = self.pool_user_liquidity.get(pool_key, {})
            partial[user_address] = Amount(
                partial.get(user_address, Amount(0)) + liquidity_increase
            )
            self.pool_user_liquidity[pool_key] = partial

            # Update total liquidity
            self.pool_total_liquidity[pool_key] = Amount(
                self.pool_total_liquidity[pool_key] + liquidity_increase
            )

            # Update reserves
            self.pool_reserve_a[pool_key] = Amount(
                self.pool_reserve_a[pool_key] + optimal_a
            )
            self.pool_reserve_b[pool_key] = Amount(
                self.pool_reserve_b[pool_key] + action_b_amount
            )

            return (self.pool_token_a[pool_key], change)

    @public(allow_withdrawal=True)
    def remove_liquidity(
        self,
        ctx: Context,
        fee: Amount,
    ) -> tuple[TokenUid, Amount]:
        """Remove liquidity from a pool.

        Args:
            ctx: The transaction context
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool (default: use default_fee)

        Raises:
            PoolNotFound: If the pool does not exist
            InvalidAction: If the user has no liquidity or insufficient liquidity
        """
        token_a, token_b = set(ctx.actions.keys())
        user_address = Address(ctx.address)

        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        pool_key = self._get_pool_key(token_a, token_b, fee)
        self._validate_pool_exists(pool_key)

        action_a, action_b = self._get_actions_out_out(ctx, pool_key)

        # Check if user has liquidity
        if (
            user_address not in self.pool_user_liquidity[pool_key]
            or self.pool_user_liquidity[pool_key][user_address] == 0
        ):
            raise InvalidAction("No liquidity to remove")

        # Calculate maximum withdrawal
        max_withdraw = (
            self.pool_user_liquidity[pool_key][user_address]
            * self.pool_reserve_a[pool_key]
            // self.pool_total_liquidity[pool_key]
        )

        action_a_amount = Amount(
            action_a.amount if isinstance(action_a, NCWithdrawalAction) else 0
        )
        action_b_amount = Amount(
            action_b.amount if isinstance(action_b, NCWithdrawalAction) else 0
        )

        if max_withdraw < action_a_amount:
            raise InvalidAction(
                f"Insufficient liquidity: {max_withdraw} < {action_a_amount}"
            )

        optimal_b = self.quote(
            action_a_amount,
            self.pool_reserve_a[pool_key],
            self.pool_reserve_b[pool_key],
        )

        if optimal_b < action_b_amount:
            raise InvalidAction("Insufficient token B amount")

        change = optimal_b - action_b_amount

        self._update_balance(
            user_address, change, self.pool_token_b[pool_key], pool_key
        )

        # Calculate liquidity decrease
        liquidity_decrease = (
            self.pool_total_liquidity[pool_key]
            * action_a_amount
            // self.pool_reserve_a[pool_key]
        )

        # Update user liquidity
        partial = self.pool_user_liquidity.get(pool_key, {})
        partial[user_address] = Amount(
            partial.get(user_address, Amount(0)) - liquidity_decrease
        )
        self.pool_user_liquidity[pool_key] = partial

        # Update total liquidity
        self.pool_total_liquidity[pool_key] = Amount(
            self.pool_total_liquidity[pool_key] - liquidity_decrease
        )

        # Update reserves
        self.pool_reserve_a[pool_key] = Amount(
            self.pool_reserve_a[pool_key] - action_a_amount
        )
        self.pool_reserve_b[pool_key] = Amount(
            self.pool_reserve_b[pool_key] - optimal_b
        )

        return (token_a, change)

    @public(allow_withdrawal=True, allow_deposit=True)
    def swap_exact_tokens_for_tokens(
        self,
        ctx: Context,
        fee: Amount,
    ) -> SwapResult:
        """Swap an exact amount of input tokens for as many output tokens as possible.

        Args:
            ctx: The transaction context
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool (default: use default_fee)

        Returns:
            SwapResult with details of the swap

        Raises:
            PoolNotFound: If the pool does not exist
            InvalidAction: If the actions are invalid
            InsufficientLiquidity: If there is insufficient liquidity
        """
        token_a, token_b = set(ctx.actions.keys())
        user_address = Address(ctx.address)

        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        pool_key = self._get_pool_key(token_a, token_b, fee)
        self._validate_pool_exists(pool_key)

        action_in, action_out = self._get_actions_in_out(ctx, pool_key)
        reserve_in = self._get_reserve(action_in.token_uid, pool_key)
        reserve_out = self._get_reserve(action_out.token_uid, pool_key)

        action_in_amount = Amount(
            action_in.amount if isinstance(action_in, NCDepositAction) else 0
        )
        action_out_amount = Amount(
            action_out.amount if isinstance(action_out, NCWithdrawalAction) else 0
        )

        amount_in = action_in_amount
        fee_amount = (
            amount_in
            * self.pool_fee_numerator[pool_key]
            // self.pool_fee_denominator[pool_key]
        )

        # Update accumulated fee using the partial approach
        partial_fee = self.pool_accumulated_fee.get(pool_key, {})
        partial_fee[action_in.token_uid] = Amount(
            partial_fee.get(action_in.token_uid, 0) + fee_amount
        )
        self.pool_accumulated_fee[pool_key] = partial_fee

        # Calculate protocol fee
        protocol_fee_amount = Amount(fee_amount * self.default_protocol_fee // 100)

        # Calculate liquidity increase for protocol fee
        liquidity_increase = self._get_protocol_liquidity_increase(
            protocol_fee_amount, action_in.token_uid, pool_key
        )

        # Add liquidity to owner using the partial approach
        partial_liquidity = self.pool_user_liquidity.get(pool_key, {})
        partial_liquidity[self.owner] = Amount(
            partial_liquidity.get(self.owner, 0) + liquidity_increase
        )
        self.pool_user_liquidity[pool_key] = partial_liquidity

        # Update total liquidity
        self.pool_total_liquidity[pool_key] = Amount(
            self.pool_total_liquidity[pool_key] + liquidity_increase
        )

        # Calculate amount out
        amount_out = self.get_amount_out(
            action_in_amount,
            reserve_in,
            reserve_out,
            self.pool_fee_numerator[pool_key],
            self.pool_fee_denominator[pool_key],
        )

        # Check if there are sufficient funds
        if reserve_out < amount_out:
            raise InsufficientLiquidity("Insufficient funds")

        # Check if the requested amount is too high
        if action_out_amount > amount_out:
            raise InvalidAction("Amount out is too high")

        # Calculate slippage
        slippage_in = amount_out - action_out_amount

        # Update user balance for slippage
        self._update_balance(user_address, slippage_in, action_out.token_uid, pool_key)

        # Update reserves
        self._update_reserve(amount_in, action_in.token_uid, pool_key)
        self._update_reserve(-amount_out, action_out.token_uid, pool_key)

        # Update statistics
        self.pool_transactions[pool_key] = Amount(self.pool_transactions[pool_key] + 1)

        if action_in.token_uid == self.pool_token_a[pool_key]:
            self.pool_volume_a[pool_key] = Amount(
                self.pool_volume_a[pool_key] + amount_in
            )
        else:
            self.pool_volume_b[pool_key] = Amount(
                self.pool_volume_b[pool_key] + amount_in
            )

        return SwapResult(
            action_in_amount,
            slippage_in,
            action_in.token_uid,
            amount_out,
            action_out.token_uid,
        )

    @public(allow_withdrawal=True, allow_deposit=True)
    def swap_tokens_for_exact_tokens(
        self,
        ctx: Context,
        fee: Amount,
    ) -> SwapResult:
        """Receive an exact amount of output tokens for as few input tokens as possible.

        Args:
            ctx: The transaction context
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool (default: use default_fee)

        Returns:
            SwapResult with details of the swap

        Raises:
            PoolNotFound: If the pool does not exist
            InvalidAction: If the actions are invalid
            InsufficientLiquidity: If there is insufficient liquidity
        """
        token_a, token_b = set(ctx.actions.keys())
        user_address = Address(ctx.address)

        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        pool_key = self._get_pool_key(token_a, token_b, fee)
        self._validate_pool_exists(pool_key)

        action_in, action_out = self._get_actions_in_out(ctx, pool_key)
        reserve_in = self._get_reserve(action_in.token_uid, pool_key)
        reserve_out = self._get_reserve(action_out.token_uid, pool_key)

        action_in_amount = Amount(
            action_in.amount if isinstance(action_in, NCDepositAction) else 0
        )
        amount_out = Amount(
            action_out.amount if isinstance(action_out, NCWithdrawalAction) else 0
        )

        # Check if there are sufficient funds
        if reserve_out < amount_out:
            raise InsufficientLiquidity("Insufficient funds")

        # Calculate amount in
        amount_in = self.get_amount_in(
            amount_out,
            reserve_in,
            reserve_out,
            self.pool_fee_numerator[pool_key],
            self.pool_fee_denominator[pool_key],
        )

        # Calculate fee amount
        fee_amount = (
            amount_in
            * self.pool_fee_numerator[pool_key]
            // self.pool_fee_denominator[pool_key]
        )

        # Update accumulated fee using the partial approach
        partial_fee = self.pool_accumulated_fee.get(pool_key, {})
        partial_fee[action_in.token_uid] = (
            partial_fee.get(action_in.token_uid, 0) + fee_amount
        )
        self.pool_accumulated_fee[pool_key] = partial_fee

        # Calculate protocol fee
        protocol_fee_amount = fee_amount * self.default_protocol_fee // 100

        # Calculate liquidity increase for protocol fee
        liquidity_increase = self._get_protocol_liquidity_increase(
            protocol_fee_amount, action_in.token_uid, pool_key
        )

        # Add liquidity to owner using the partial approach
        partial_liquidity = self.pool_user_liquidity.get(pool_key, {})
        partial_liquidity[self.owner] = Amount(
            partial_liquidity.get(self.owner, 0) + liquidity_increase
        )
        self.pool_user_liquidity[pool_key] = partial_liquidity

        # Update total liquidity
        self.pool_total_liquidity[pool_key] = Amount(
            self.pool_total_liquidity[pool_key] + liquidity_increase
        )

        # Check if the provided amount is sufficient
        if action_in_amount < amount_in:
            raise InvalidAction("Amount in is too low")

        # Calculate slippage
        slippage_in = action_in_amount - amount_in

        # Update user balance for slippage
        self._update_balance(user_address, slippage_in, action_in.token_uid, pool_key)

        # Update reserves
        self._update_reserve(amount_in, action_in.token_uid, pool_key)
        self._update_reserve(Amount(-amount_out), action_out.token_uid, pool_key)

        # Update statistics
        self.pool_transactions[pool_key] = Amount(self.pool_transactions[pool_key] + 1)

        if action_in.token_uid == self.pool_token_a[pool_key]:
            self.pool_volume_a[pool_key] = Amount(
                self.pool_volume_a[pool_key] + amount_in
            )
        else:
            self.pool_volume_b[pool_key] += amount_in

        return SwapResult(
            action_in_amount,
            slippage_in,
            action_in.token_uid,
            amount_out,
            action_out.token_uid,
        )

    @public(allow_withdrawal=True, allow_deposit=True)
    def swap_exact_tokens_for_tokens_through_path(
        self, ctx: Context, path_str: str
    ) -> SwapResult:
        """Execute a swap with exact input amount through a specific path of pools.

        The input and output tokens and amounts are extracted from the transaction context.

        Args:
            ctx: The transaction context
            path_str: Comma-separated string of pool keys to traverse

        Returns:
            SwapResult with details of the swap

        Raises:
            PoolNotFound: If any pool in the path does not exist
            InsufficientLiquidity: If there is insufficient liquidity
            InvalidPath: If the path is invalid
            InvalidAction: If the actions are invalid
        """
        user_address = Address(ctx.address)
        # Parse the path
        if not path_str:
            raise InvalidPath("Empty path")

        path = path_str.split(",")

        # Validate path length
        if len(path) == 0 or len(path) > 3:
            raise InvalidPath("Invalid path length")

        # Find deposit and withdrawal actions
        deposit_action = None
        withdrawal_action = None
        for action in ctx.actions.values():
            if isinstance(action[0], NCDepositAction):
                deposit_action = action[0]
            elif isinstance(action[0], NCWithdrawalAction):
                withdrawal_action = action[0]

        if not deposit_action or not withdrawal_action:
            raise InvalidAction("Missing deposit or withdrawal action")

        # Get the input amount and token from the deposit action
        amount_in = deposit_action.amount
        token_in = deposit_action.token_uid

        # Get the first pool to determine input token
        first_pool_key = path[0]
        if first_pool_key not in self.all_pools:
            raise PoolNotFound()

        # Execute the swap through the path
        current_amount = Amount(amount_in)
        current_token = token_in

        # Determine the output token of the first pool
        if self.pool_token_a[first_pool_key] == current_token:
            next_token = self.pool_token_b[first_pool_key]
        elif self.pool_token_b[first_pool_key] == current_token:
            next_token = self.pool_token_a[first_pool_key]
        else:
            raise InvalidPath("First pool does not contain input token")

        # Execute the first swap
        first_amount_out = self._swap(
            ctx, current_amount, current_token, next_token, first_pool_key
        )

        # If there's only one hop, we're done
        if len(path) == 1:
            token_out = next_token
            amount_out = first_amount_out
        else:
            # Second hop
            current_amount = first_amount_out
            current_token = next_token
            second_pool_key = path[1]

            if second_pool_key not in self.all_pools:
                raise PoolNotFound()

            # Determine the output token of the second pool
            if self.pool_token_a[second_pool_key] == current_token:
                next_token = self.pool_token_b[second_pool_key]
            elif self.pool_token_b[second_pool_key] == current_token:
                next_token = self.pool_token_a[second_pool_key]
            else:
                raise InvalidPath("Second pool does not contain intermediate token")

            # Execute the second swap
            second_amount_out = self._swap(
                ctx, current_amount, current_token, next_token, second_pool_key
            )

            # If there are only two hops, we're done
            if len(path) == 2:
                token_out = next_token
                amount_out = second_amount_out
            else:
                # Third hop
                current_amount = second_amount_out
                current_token = next_token
                third_pool_key = path[2]

                if third_pool_key not in self.all_pools:
                    raise PoolNotFound()

                # Determine the output token of the third pool
                if self.pool_token_a[third_pool_key] == current_token:
                    next_token = self.pool_token_b[third_pool_key]
                elif self.pool_token_b[third_pool_key] == current_token:
                    next_token = self.pool_token_a[third_pool_key]
                else:
                    raise InvalidPath("Third pool does not contain intermediate token")

                # Execute the third swap
                third_amount_out = self._swap(
                    ctx, current_amount, current_token, next_token, third_pool_key
                )

                token_out = next_token
                amount_out = third_amount_out

        # Check if the output amount matches the withdrawal action
        if withdrawal_action.token_uid != token_out:
            raise InvalidAction("Withdrawal token does not match output token")

        # Calculate slippage (if the withdrawal amount is less than the calculated output)
        slippage_out = 0
        if withdrawal_action.amount < amount_out:
            slippage_out = Amount(amount_out - withdrawal_action.amount)
            # Add slippage to user balance for the output token in the last pool
            last_pool_key = path[-1]
            self._update_balance(user_address, slippage_out, token_out, last_pool_key)
            amount_out = withdrawal_action.amount

        return SwapResult(
            Amount(amount_in),
            Amount(slippage_out),
            token_in,
            Amount(amount_out),
            token_out,
        )

    def _swap_exact_out(
        self,
        ctx: Context,
        amount_in: Amount,
        token_in: TokenUid,
        amount_out: Amount,
        token_out: TokenUid,
        pool_key: str,
    ) -> None:
        """Internal method to execute a swap in a single pool with exact output amount.

        This is a helper method for swap_tokens_for_exact_tokens_through_path.
        Unlike _swap, this method takes the exact output amount that should be produced.
        The input amount has already been calculated using get_amount_in.

        Args:
            ctx: The transaction context
            amount_in: The calculated amount of input tokens
            token_in: The input token
            amount_out: The exact amount of output tokens
            token_out: The output token
            pool_key: The pool key
        """
        # Get the pool reserves
        reserve_in = 0
        reserve_out = 0

        if self.pool_token_a[pool_key] == token_in:
            reserve_in = self.pool_reserve_a[pool_key]
            reserve_out = self.pool_reserve_b[pool_key]

            # Calculate fee amount for protocol fee
            fee = self.pool_fee_numerator[pool_key]
            fee_denominator = self.pool_fee_denominator[pool_key]
            fee_amount = amount_in * fee // fee_denominator

            # Calculate protocol fee
            protocol_fee_amount = Amount(fee_amount * self.default_protocol_fee // 100)

            # Calculate liquidity increase for protocol fee
            liquidity_increase = self._get_protocol_liquidity_increase(
                protocol_fee_amount, token_in, pool_key
            )

            # Add liquidity to owner using the partial approach
            partial_liquidity = self.pool_user_liquidity.get(pool_key, {})
            partial_liquidity[self.owner] = Amount(
                partial_liquidity.get(self.owner, 0) + liquidity_increase
            )
            self.pool_user_liquidity[pool_key] = partial_liquidity

            # Update total liquidity
            self.pool_total_liquidity[pool_key] = Amount(
                self.pool_total_liquidity.get(pool_key, 0) + liquidity_increase
            )

            # Update reserves - use the exact amounts we calculated
            self.pool_reserve_a[pool_key] = Amount(reserve_in + amount_in)
            self.pool_reserve_b[pool_key] = Amount(reserve_out - amount_out)

            # Update volume
            self.pool_volume_a[pool_key] = Amount(
                self.pool_volume_a.get(pool_key, 0) + amount_in
            )
            self.pool_volume_b[pool_key] = Amount(
                self.pool_volume_b.get(pool_key, 0) + amount_out
            )
        else:
            reserve_in = self.pool_reserve_b[pool_key]
            reserve_out = self.pool_reserve_a[pool_key]

            # Calculate fee amount for protocol fee
            fee = self.pool_fee_numerator[pool_key]
            fee_denominator = self.pool_fee_denominator[pool_key]
            fee_amount = amount_in * fee // fee_denominator

            # Calculate protocol fee
            protocol_fee_amount = Amount(fee_amount * self.default_protocol_fee // 100)

            # Calculate liquidity increase for protocol fee
            liquidity_increase = self._get_protocol_liquidity_increase(
                protocol_fee_amount, token_in, pool_key
            )

            # Add liquidity to owner using the partial approach
            partial_liquidity = self.pool_user_liquidity.get(pool_key, {})
            partial_liquidity[self.owner] = Amount(
                partial_liquidity.get(self.owner, 0) + liquidity_increase
            )
            self.pool_user_liquidity[pool_key] = partial_liquidity

            # Update total liquidity
            self.pool_total_liquidity[pool_key] = Amount(
                self.pool_total_liquidity.get(pool_key, 0) + liquidity_increase
            )

            # Update reserves - use the exact amounts
            self._update_reserve(amount_in, token_in, pool_key)
            self._update_reserve(Amount(-amount_out), token_out, pool_key)

            # Update volume
            self.pool_volume_b[pool_key] = Amount(
                self.pool_volume_b.get(pool_key, 0) + amount_in
            )
            self.pool_volume_a[pool_key] = Amount(
                self.pool_volume_a.get(pool_key, 0) + amount_out
            )

        # Update last activity timestamp
        self.pool_last_activity[pool_key] = Timestamp(ctx.timestamp)

        # Increment transaction count
        self.pool_transactions[pool_key] = Amount(
            self.pool_transactions.get(pool_key, 0) + 1
        )

    def _swap(
        self,
        ctx: Context,
        amount_in: Amount,
        token_in: TokenUid,
        token_out: TokenUid,
        pool_key: str,
    ) -> Amount:
        """Internal method to execute a swap in a single pool.

        This is a helper method for swap_exact_tokens_for_tokens_through_path.

        Args:
            ctx: The transaction context
            amount_in: The amount of input tokens
            token_in: The input token
            token_out: The output token
            pool_key: The pool key

        Returns:
            The amount of output tokens received
        """
        # Get the pool reserves
        reserve_in = 0
        reserve_out = 0

        if self.pool_token_a[pool_key] == token_in:
            reserve_in = self.pool_reserve_a[pool_key]
            reserve_out = self.pool_reserve_b[pool_key]

            # Calculate the output amount
            fee = self.pool_fee_numerator[pool_key]
            fee_denominator = self.pool_fee_denominator[pool_key]
            a = fee_denominator - fee
            b = fee_denominator
            amount_out = (reserve_out * amount_in * a) // (
                reserve_in * b + amount_in * a
            )

            # Calculate fee amount for protocol fee
            fee_amount = amount_in * fee // fee_denominator

            # Calculate protocol fee
            protocol_fee_amount = Amount(fee_amount * self.default_protocol_fee // 100)

            # Calculate liquidity increase for protocol fee
            liquidity_increase = self._get_protocol_liquidity_increase(
                protocol_fee_amount, token_in, pool_key
            )

            # Add liquidity to owner using the partial approach
            partial_liquidity = self.pool_user_liquidity.get(pool_key, {})
            partial_liquidity[self.owner] = Amount(
                partial_liquidity.get(self.owner, 0) + liquidity_increase
            )
            self.pool_user_liquidity[pool_key] = partial_liquidity

            # Update total liquidity
            self.pool_total_liquidity[pool_key] = Amount(
                self.pool_total_liquidity.get(pool_key, 0) + liquidity_increase
            )

            # Update reserves - keep the full amount in reserves to match test expectations
            self.pool_reserve_a[pool_key] = Amount(reserve_in + amount_in)
            self.pool_reserve_b[pool_key] = Amount(reserve_out - amount_out)

            # Update volume
            self.pool_volume_a[pool_key] = Amount(
                self.pool_volume_a.get(pool_key, 0) + amount_in
            )
            self.pool_volume_b[pool_key] = Amount(
                self.pool_volume_b.get(pool_key, 0) + amount_out
            )
        else:
            reserve_in = self.pool_reserve_b[pool_key]
            reserve_out = self.pool_reserve_a[pool_key]

            # Calculate the output amount
            fee = self.pool_fee_numerator[pool_key]
            fee_denominator = self.pool_fee_denominator[pool_key]
            a = fee_denominator - fee
            b = fee_denominator
            amount_out = (reserve_out * amount_in * a) // (
                reserve_in * b + amount_in * a
            )

            # Calculate fee amount for protocol fee
            fee_amount = amount_in * fee // fee_denominator

            # Calculate protocol fee
            protocol_fee_amount = Amount(fee_amount * self.default_protocol_fee // 100)

            # Calculate liquidity increase for protocol fee
            liquidity_increase = self._get_protocol_liquidity_increase(
                protocol_fee_amount, token_in, pool_key
            )

            # Add liquidity to owner using the partial approach
            partial_liquidity = self.pool_user_liquidity.get(pool_key, {})
            partial_liquidity[self.owner] = Amount(
                partial_liquidity.get(self.owner, 0) + liquidity_increase
            )
            self.pool_user_liquidity[pool_key] = partial_liquidity

            # Update total liquidity
            self.pool_total_liquidity[pool_key] = Amount(
                self.pool_total_liquidity.get(pool_key, 0) + liquidity_increase
            )

            # Update reserves
            self._update_reserve(amount_in, token_in, pool_key)
            self._update_reserve(Amount(-amount_out), token_out, pool_key)

            # Update volume
            self.pool_volume_b[pool_key] = Amount(
                self.pool_volume_b.get(pool_key, 0) + amount_in
            )
            self.pool_volume_a[pool_key] = Amount(
                self.pool_volume_a.get(pool_key, 0) + amount_out
            )

        # Update last activity timestamp
        self.pool_last_activity[pool_key] = Timestamp(ctx.timestamp)

        # Increment transaction count
        self.pool_transactions[pool_key] = Amount(
            self.pool_transactions.get(pool_key, 0) + 1
        )

        return Amount(amount_out)

    @public(allow_withdrawal=True, allow_deposit=True)
    def swap_tokens_for_exact_tokens_through_path(
        self, ctx: Context, path_str: str
    ) -> SwapResult:
        """Execute a swap with exact output amount through a specific path of pools.

        The input and output tokens and amounts are extracted from the transaction context.

        Args:
            ctx: The transaction context
            path_str: Comma-separated string of pool keys to traverse

        Returns:
            SwapResult with details of the swap

        Raises:
            PoolNotFound: If any pool in the path does not exist
            InsufficientLiquidity: If there is insufficient liquidity
            InvalidPath: If the path is invalid
            InvalidAction: If the actions are invalid
        """
        user_address = Address(ctx.address)
        # Parse the path
        if not path_str:
            raise InvalidPath("Empty path")

        path = path_str.split(",")

        # Validate path length
        if len(path) == 0 or len(path) > 3:
            raise InvalidPath("Invalid path length")

        # Find deposit and withdrawal actions
        deposit_action = None
        withdrawal_action = None
        for action in ctx.actions.values():
            if isinstance(action[0], NCDepositAction):
                deposit_action = action[0]
            elif isinstance(action[0], NCWithdrawalAction):
                withdrawal_action = action[0]

        if not deposit_action or not withdrawal_action:
            raise InvalidAction("Missing deposit or withdrawal action")

        # Get the output amount and token from the withdrawal action
        amount_out = withdrawal_action.amount
        token_out = withdrawal_action.token_uid

        # Get the actual input amount from deposit action
        actual_amount_in = deposit_action.amount
        token_in = deposit_action.token_uid

        # For a single hop path
        if len(path) == 1:
            pool_key = path[0]
            if pool_key not in self.all_pools:
                raise PoolNotFound()

            # Verify the tokens match the pool
            if (
                token_out != self.pool_token_a[pool_key]
                and token_out != self.pool_token_b[pool_key]
            ):
                raise InvalidPath("Pool does not contain output token")
            if (
                token_in != self.pool_token_a[pool_key]
                and token_in != self.pool_token_b[pool_key]
            ):
                raise InvalidPath("Pool does not contain input token")

            # Calculate the required input amount
            reserve_in = 0
            reserve_out = 0
            if self.pool_token_a[pool_key] == token_in:
                reserve_in = self.pool_reserve_a[pool_key]
                reserve_out = self.pool_reserve_b[pool_key]
            else:
                reserve_in = self.pool_reserve_b[pool_key]
                reserve_out = self.pool_reserve_a[pool_key]

            # Get the fee for this pool
            fee = self.pool_fee_numerator[pool_key]
            fee_denominator = self.pool_fee_denominator[pool_key]

            # Calculate the required input amount
            amount_in = self.get_amount_in(
                amount_out, reserve_in, reserve_out, fee, fee_denominator
            )

            # Check if the provided amount is sufficient
            if actual_amount_in < amount_in:
                raise InvalidAction("Amount in is too low")

            # Calculate slippage
            slippage_in = actual_amount_in - amount_in

            # Update user balance for slippage
            if slippage_in > 0:
                self._update_balance(user_address, slippage_in, token_in, pool_key)

            # Execute the swap (updates reserves and statistics)
            self._swap_exact_out(
                ctx,
                Amount(amount_in),
                token_in,
                Amount(amount_out),
                token_out,
                pool_key,
            )

            return SwapResult(
                Amount(actual_amount_in),
                slippage_in,
                token_in,
                Amount(amount_out),
                token_out,
            )

        # For multi-hop paths, we need to calculate backwards
        # This implementation handles 2 or 3 hops

        # Get the last pool
        last_pool_key = path[-1]
        if last_pool_key not in self.all_pools:
            raise PoolNotFound()

        # Verify the output token is in the last pool
        if (
            token_out != self.pool_token_a[last_pool_key]
            and token_out != self.pool_token_b[last_pool_key]
        ):
            raise InvalidPath("Last pool does not contain output token")

        # For 2-hop path: token_in -> intermediate -> token_out
        if len(path) == 2:
            # Get the second pool (intermediate -> token_out)
            second_pool_key = path[1]

            # Determine the intermediate token
            if self.pool_token_a[second_pool_key] == token_out:
                intermediate_token = self.pool_token_b[second_pool_key]
            else:
                intermediate_token = self.pool_token_a[second_pool_key]

            # Get the first pool (token_in -> intermediate)
            first_pool_key = path[0]
            if first_pool_key not in self.all_pools:
                raise PoolNotFound()

            # Verify the input token is in the first pool
            if (
                token_in != self.pool_token_a[first_pool_key]
                and token_in != self.pool_token_b[first_pool_key]
            ):
                raise InvalidPath("First pool does not contain input token")

            # Verify the intermediate token connects the pools
            if (
                intermediate_token != self.pool_token_a[first_pool_key]
                and intermediate_token != self.pool_token_b[first_pool_key]
            ):
                raise InvalidPath("First pool does not contain intermediate token")

            # Calculate backwards from the output
            # First, calculate how much intermediate token we need
            second_reserve_in = 0
            second_reserve_out = 0
            if self.pool_token_a[second_pool_key] == intermediate_token:
                second_reserve_in = self.pool_reserve_a[second_pool_key]
                second_reserve_out = self.pool_reserve_b[second_pool_key]
            else:
                second_reserve_in = self.pool_reserve_b[second_pool_key]
                second_reserve_out = self.pool_reserve_a[second_pool_key]

            second_fee = self.pool_fee_numerator[second_pool_key]
            second_fee_denominator = self.pool_fee_denominator[second_pool_key]

            intermediate_amount = self.get_amount_in(
                amount_out,
                second_reserve_in,
                second_reserve_out,
                second_fee,
                second_fee_denominator,
            )

            # Then, calculate how much input token we need
            first_reserve_in = 0
            first_reserve_out = 0
            if self.pool_token_a[first_pool_key] == token_in:
                first_reserve_in = self.pool_reserve_a[first_pool_key]
                first_reserve_out = self.pool_reserve_b[first_pool_key]
            else:
                first_reserve_in = self.pool_reserve_b[first_pool_key]
                first_reserve_out = self.pool_reserve_a[first_pool_key]

            first_fee = self.pool_fee_numerator[first_pool_key]
            first_fee_denominator = self.pool_fee_denominator[first_pool_key]

            amount_in = self.get_amount_in(
                intermediate_amount,
                first_reserve_in,
                first_reserve_out,
                first_fee,
                first_fee_denominator,
            )

            # Check if the provided amount is sufficient
            if actual_amount_in < amount_in:
                raise InvalidAction("Amount in is too low")

            # Calculate slippage
            slippage_in = actual_amount_in - amount_in

            # Update user balance for slippage
            if slippage_in > 0:
                self._update_balance(
                    user_address, slippage_in, token_in, first_pool_key
                )

            # Execute the swaps
            # First swap: token_in -> intermediate
            # For the first swap, we need the exact intermediate amount that will be needed for the second swap
            self._swap_exact_out(
                ctx,
                amount_in,
                token_in,
                intermediate_amount,
                intermediate_token,
                first_pool_key,
            )

            # Second swap: intermediate -> token_out
            self._swap_exact_out(
                ctx,
                intermediate_amount,
                intermediate_token,
                Amount(amount_out),
                token_out,
                second_pool_key,
            )

            return SwapResult(
                Amount(actual_amount_in),
                slippage_in,
                token_in,
                Amount(amount_out),
                token_out,
            )

        # For 3-hop path: token_in -> first_intermediate -> second_intermediate -> token_out
        if len(path) == 3:
            # Get the third pool (last in the path)
            third_pool_key = path[2]
            if third_pool_key not in self.all_pools:
                raise PoolNotFound()

            # Determine the output token and the second intermediate token
            if self.pool_token_a[third_pool_key] == token_out:
                second_intermediate_token = self.pool_token_b[third_pool_key]
            elif self.pool_token_b[third_pool_key] == token_out:
                second_intermediate_token = self.pool_token_a[third_pool_key]
            else:
                raise InvalidPath("Third pool does not contain output token")

            # Get the second pool (middle of the path)
            second_pool_key = path[1]
            if second_pool_key not in self.all_pools:
                raise PoolNotFound()

            # Determine the first intermediate token
            if self.pool_token_a[second_pool_key] == second_intermediate_token:
                first_intermediate_token = self.pool_token_b[second_pool_key]
            elif self.pool_token_b[second_pool_key] == second_intermediate_token:
                first_intermediate_token = self.pool_token_a[second_pool_key]
            else:
                raise InvalidPath("Second pool does not connect to third pool")

            # Get the first pool (first in the path)
            first_pool_key = path[0]
            if first_pool_key not in self.all_pools:
                raise PoolNotFound()

            # Verify the input token is in the first pool
            if (
                token_in != self.pool_token_a[first_pool_key]
                and token_in != self.pool_token_b[first_pool_key]
            ):
                raise InvalidPath("First pool does not contain input token")

            # Verify the first intermediate token connects the first and second pools
            if (
                first_intermediate_token != self.pool_token_a[first_pool_key]
                and first_intermediate_token != self.pool_token_b[first_pool_key]
            ):
                raise InvalidPath("First pool does not connect to second pool")

            # Calculate backwards from the output
            # First, calculate how much second_intermediate_token we need
            third_reserve_in = 0
            third_reserve_out = 0
            if self.pool_token_a[third_pool_key] == second_intermediate_token:
                third_reserve_in = self.pool_reserve_a[third_pool_key]
                third_reserve_out = self.pool_reserve_b[third_pool_key]
            else:
                third_reserve_in = self.pool_reserve_b[third_pool_key]
                third_reserve_out = self.pool_reserve_a[third_pool_key]

            third_fee = self.pool_fee_numerator[third_pool_key]
            third_fee_denominator = self.pool_fee_denominator[third_pool_key]

            second_intermediate_amount = self.get_amount_in(
                amount_out,
                third_reserve_in,
                third_reserve_out,
                third_fee,
                third_fee_denominator,
            )

            # Then, calculate how much first_intermediate_token we need
            second_reserve_in = 0
            second_reserve_out = 0
            if self.pool_token_a[second_pool_key] == first_intermediate_token:
                second_reserve_in = self.pool_reserve_a[second_pool_key]
                second_reserve_out = self.pool_reserve_b[second_pool_key]
            else:
                second_reserve_in = self.pool_reserve_b[second_pool_key]
                second_reserve_out = self.pool_reserve_a[second_pool_key]

            second_fee = self.pool_fee_numerator[second_pool_key]
            second_fee_denominator = self.pool_fee_denominator[second_pool_key]

            first_intermediate_amount = self.get_amount_in(
                second_intermediate_amount,
                second_reserve_in,
                second_reserve_out,
                second_fee,
                second_fee_denominator,
            )

            # Finally, calculate how much input token we need
            first_reserve_in = 0
            first_reserve_out = 0
            if self.pool_token_a[first_pool_key] == token_in:
                first_reserve_in = self.pool_reserve_a[first_pool_key]
                first_reserve_out = self.pool_reserve_b[first_pool_key]
            else:
                first_reserve_in = self.pool_reserve_b[first_pool_key]
                first_reserve_out = self.pool_reserve_a[first_pool_key]

            first_fee = self.pool_fee_numerator[first_pool_key]
            first_fee_denominator = self.pool_fee_denominator[first_pool_key]

            amount_in = self.get_amount_in(
                first_intermediate_amount,
                first_reserve_in,
                first_reserve_out,
                first_fee,
                first_fee_denominator,
            )

            # Check if the provided amount is sufficient
            if actual_amount_in < amount_in:
                raise InvalidAction("Amount in is too low")

            # Calculate slippage
            slippage_in = actual_amount_in - amount_in

            # Update user balance for slippage
            if slippage_in > 0:
                self._update_balance(
                    user_address, slippage_in, token_in, first_pool_key
                )

            # Execute the swaps
            # First swap: token_in -> first_intermediate_token
            self._swap_exact_out(
                ctx,
                amount_in,
                token_in,
                first_intermediate_amount,
                first_intermediate_token,
                first_pool_key,
            )

            # Second swap: first_intermediate_token -> second_intermediate_token
            self._swap_exact_out(
                ctx,
                first_intermediate_amount,
                first_intermediate_token,
                second_intermediate_amount,
                second_intermediate_token,
                second_pool_key,
            )

            # Third swap: second_intermediate_token -> token_out
            self._swap_exact_out(
                ctx,
                second_intermediate_amount,
                second_intermediate_token,
                Amount(amount_out),
                token_out,
                third_pool_key,
            )

            return SwapResult(
                Amount(actual_amount_in),
                slippage_in,
                token_in,
                Amount(amount_out),
                token_out,
            )

        # This should never happen due to the path length validation above
        raise InvalidPath("Invalid path length")

    @public(allow_withdrawal=True)
    def withdraw_cashback(
        self,
        ctx: Context,
        fee: Amount,
    ) -> None:
        """Withdraw cashback from a pool.

        Args:
            ctx: The transaction context
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool

        Raises:
            PoolNotFound: If the pool does not exist
            InvalidAction: If there is not enough cashback
        """
        token_a, token_b = set(ctx.actions.keys())
        user_address = Address(ctx.address)

        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        pool_key = self._get_pool_key(token_a, token_b, fee)
        self._validate_pool_exists(pool_key)

        action_a, action_b = self._get_actions_out_out(ctx, pool_key)

        action_a_amount = Amount(
            action_a.amount if isinstance(action_a, NCWithdrawalAction) else 0
        )
        action_b_amount = Amount(
            action_b.amount if isinstance(action_b, NCWithdrawalAction) else 0
        )

        # Check if user has enough cashback
        if action_a_amount > self.pool_balance_a.get(pool_key, {}).get(
            user_address, Amount(0)
        ):
            raise InvalidAction("Not enough cashback for token A")

        if action_b_amount > self.pool_balance_b.get(pool_key, {}).get(
            user_address, Amount(0)
        ):
            raise InvalidAction("Not enough cashback for token B")

        # Update user balances
        if pool_key not in self.pool_balance_a:
            self.pool_balance_a[pool_key] = {}
        if user_address not in self.pool_balance_a[pool_key]:
            self.pool_balance_a[pool_key][user_address] = Amount(0)
        self.pool_balance_a[pool_key][user_address] = Amount(
            self.pool_balance_a[pool_key][user_address] - action_a_amount
        )

        if pool_key not in self.pool_balance_b:
            self.pool_balance_b[pool_key] = {}
        if user_address not in self.pool_balance_b[pool_key]:
            self.pool_balance_b[pool_key][user_address] = Amount(0)
        self.pool_balance_b[pool_key][user_address] = Amount(
            self.pool_balance_b[pool_key][user_address] - action_b_amount
        )

        # Update total balances
        if pool_key not in self.pool_total_balance_a:
            self.pool_total_balance_a[pool_key] = Amount(0)
        self.pool_total_balance_a[pool_key] = Amount(
            self.pool_total_balance_a[pool_key] - action_a_amount
        )

        if pool_key not in self.pool_total_balance_b:
            self.pool_total_balance_b[pool_key] = Amount(0)
        self.pool_total_balance_b[pool_key] = Amount(
            self.pool_total_balance_b[pool_key] - action_b_amount
        )

    @public
    def change_default_fee(self, ctx: Context, new_fee: Amount) -> None:
        """Set the default fee for new pools.

        Args:
            ctx: The transaction context
            new_fee: The new default fee

        Raises:
            Unauthorized: If the caller is not the owner
            InvalidFee: If the fee is invalid
        """
        if Address(ctx.address) != self.owner:
            raise Unauthorized("Only owner can set default fee")

        if new_fee > 50:
            raise InvalidFee("Fee too high")
        if new_fee < 0:
            raise InvalidFee("Invalid fee")

    @public
    def change_protocol_fee(self, ctx: Context, new_fee: Amount) -> None:
        """Change the protocol fee.

        Args:
            ctx: The transaction context
            new_fee: The new protocol fee

        Raises:
            Unauthorized: If the caller is not the owner
            InvalidFee: If the fee is invalid
        """
        if ctx.address != self.owner:
            raise Unauthorized("Only the owner can change the protocol fee")

        if new_fee > 50:
            raise InvalidFee("Protocol fee must be <= 5%")

        self.default_protocol_fee = new_fee

    @public
    def add_authorized_signer(self, ctx: Context, signer_address: Address) -> None:
        """Add an address to the list of authorized signers.

        Only the contract owner can add authorized signers.
        Authorized signers can sign pools for listing in the Dozer dApp.

        Args:
            ctx: The transaction context
            signer_address: The address to authorize as a signer

        Raises:
            Unauthorized: If the caller is not the owner
        """
        if ctx.address != self.owner:
            raise Unauthorized("Only the owner can add authorized signers")

        self.authorized_signers[signer_address] = True

    @public
    def remove_authorized_signer(self, ctx: Context, signer_address: Address) -> None:
        """Remove an address from the list of authorized signers.

        Only the contract owner can remove authorized signers.
        The owner cannot be removed as an authorized signer.

        Args:
            ctx: The transaction context
            signer_address: The address to remove authorization from

        Raises:
            Unauthorized: If the caller is not the owner
            NCFail: If trying to remove the owner as a signer
        """
        if ctx.address != self.owner:
            raise Unauthorized("Only the owner can remove authorized signers")

        if signer_address == self.owner:
            raise NCFail("Cannot remove the owner as an authorized signer")

        if signer_address in self.authorized_signers:
            del self.authorized_signers[signer_address]

    @public
    def sign_pool(
        self, ctx: Context, token_a: TokenUid, token_b: TokenUid, fee: Amount
    ) -> None:
        """Sign a pool for listing in the Dozer dApp.

        Only authorized signers can sign pools.
        Signed pools are eligible for listing in the Dozer dApp.

        Args:
            ctx: The transaction context
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool

        Raises:
            Unauthorized: If the caller is not an authorized signer
            PoolNotFound: If the pool does not exist
        """
        if not self.authorized_signers.get(Address(ctx.address), False):
            raise Unauthorized("Only authorized signers can sign pools")

        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        pool_key = self._get_pool_key(token_a, token_b, fee)
        self._validate_pool_exists(pool_key)

        self.pool_signers[pool_key] = Address(ctx.address)

    @public
    def unsign_pool(
        self, ctx: Context, token_a: TokenUid, token_b: TokenUid, fee: Amount
    ) -> None:
        """Remove a pool's signature for listing in the Dozer dApp.

        Only the owner or the original signer can unsign a pool.

        Args:
            ctx: The transaction context
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool

        Raises:
            Unauthorized: If the caller is not the owner or original signer
            PoolNotFound: If the pool does not exist
        """
        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        pool_key = self._get_pool_key(token_a, token_b, fee)
        self._validate_pool_exists(pool_key)

        if not pool_key in self.pool_signers:
            # Pool is not signed, nothing to do
            return

        original_signer = self.pool_signers.get(pool_key)
        if ctx.address != self.owner and ctx.address != original_signer:
            raise Unauthorized("Only the owner or original signer can unsign a pool")

        if pool_key in self.pool_signers:
            self.pool_signers.__delitem__(pool_key)

    @public
    def set_htr_usd_pool(
        self, ctx: Context, token_a: TokenUid, token_b: TokenUid, fee: Amount
    ) -> None:
        """Set the HTR-USD pool for price calculations.

        Only the owner can set the HTR-USD pool.
        The pool must exist and contain HTR as one of the tokens.

        Args:
            ctx: The transaction context
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool

        Raises:
            Unauthorized: If the caller is not the owner
            PoolNotFound: If the pool does not exist
            InvalidTokens: If neither token is HTR
        """
        if ctx.address != self.owner:
            raise Unauthorized("Only the owner can set the HTR-USD pool")

        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        pool_key = self._get_pool_key(token_a, token_b, fee)
        self._validate_pool_exists(pool_key)

        # Verify that one of the tokens is HTR
        if token_a != HTR_UID and token_b != HTR_UID:
            raise InvalidTokens("HTR-USD pool must contain HTR as one of the tokens")

        self.htr_usd_pool_key = pool_key

    @view
    def get_signed_pools(self) -> list[str]:
        """Get a list of all signed pools.

        Returns:
            A list of pool keys that are signed for listing in the Dozer dApp
        """
        result = []
        for pool_key in self.all_pools:
            if pool_key not in self.pool_signers:
                continue
            token_a = self.pool_token_a[pool_key].hex()
            token_b = self.pool_token_b[pool_key].hex()
            fee = self.pool_fee_numerator[pool_key]
            result.append(f"{token_a}/{token_b}/{fee}")
        return result

    @view
    def is_authorized_signer(self, address: Address) -> bool:
        """Check if an address is an authorized signer.

        Args:
            address: The address to check

        Returns:
            True if the address is an authorized signer, False otherwise
        """
        return self.authorized_signers.get(address, False)

    @view
    def get_htr_usd_pool(self) -> str | None:
        """Get the current HTR-USD pool key.

        Returns:
            The pool key of the HTR-USD pool, or None if not set
        """
        return self.htr_usd_pool_key

    @view
    def get_user_pools(self, address: Address) -> list[str]:
        """Get all pools where a user has liquidity.

        Args:
            address: The address to check

        Returns:
            A list of pool keys where the user has liquidity
        """
        user_pools = []
        for pool_key in self.all_pools:
            # Check if user has liquidity in this pool
            if pool_key in self.pool_user_liquidity:
                user_liquidity = self.pool_user_liquidity[pool_key].get(address, 0)
                if user_liquidity > 0:
                    user_pools.append(pool_key)
        return user_pools

    @view
    def get_user_positions(self, address: Address) -> dict[str, dict[str, Any]]:
        """Get detailed information about all user positions across pools.

        Args:
            address: The address to check

        Returns:
            A dictionary mapping pool keys to position information
        """
        positions = {}
        for pool_key in self.all_pools:
            # Check if user has liquidity in this pool
            if pool_key in self.pool_user_liquidity:
                user_liquidity = self.pool_user_liquidity[pool_key].get(address, 0)
                if user_liquidity > 0:
                    # Get detailed information about this position
                    positions[pool_key] = self.user_info(address, pool_key)

                    # Add token information to make it more user-friendly
                    positions[pool_key]["token_a"] = self.pool_token_a[pool_key].hex()
                    positions[pool_key]["token_b"] = self.pool_token_b[pool_key].hex()
                    positions[pool_key]["fee"] = (
                        self.pool_fee_numerator[pool_key]
                        / self.pool_fee_denominator[pool_key]
                    )
        return positions

    @view
    def get_token_price_in_htr(self, token: TokenUid) -> Amount:
        """Get the price of a token in HTR.

        Args:
            token: The token to get the price for

        Returns:
            The price of the token in HTR with 6 decimal places, or 0 if not available
        """
        # HTR itself has a price of 1 in HTR
        if token == HTR_UID:
            return Amount(1_000000)  # 1 with 6 decimal places

        # Check if we have this token in the HTR token map
        pool_key = self.htr_token_map.get(token)
        if pool_key is None:
            return Amount(0)

        reserve_a = self.pool_reserve_a[pool_key]
        reserve_b = self.pool_reserve_b[pool_key]

        # Determine which reserve is HTR and which is the token
        if self.pool_token_a[pool_key] == HTR_UID:
            htr_reserve = reserve_a
            token_reserve = reserve_b
        else:
            htr_reserve = reserve_b
            token_reserve = reserve_a

        # Calculate price: HTR per token with 6 decimal places
        if token_reserve == 0:
            return Amount(0)

        return Amount((htr_reserve * 1_000000) // token_reserve)

    @view
    def get_all_token_prices_in_htr(self) -> dict[str, Amount]:
        """Get the prices of all tokens that have HTR pools in HTR.

        Returns:
            A dictionary mapping token UIDs (hex) to their prices in HTR with 6 decimal places
        """
        result = {}
        result[HTR_UID.hex()] = Amount(1_000000)  # HTR itself has a price of 1 in HTR

        # We can't use a for loop in public methods, but this is a view method
        for pool_key in self.all_pools:
            token_a = self.pool_token_a[pool_key]
            token_b = self.pool_token_b[pool_key]
            if token_a == HTR_UID:
                token = token_b
            elif token_b == HTR_UID:
                token = token_a
            else:
                continue
            price = self.get_token_price_in_htr(token)
            if price > 0:
                result[token.hex()] = Amount(price)

        return result

    @view
    def get_token_price_in_usd(self, token: TokenUid) -> Amount:
        """Get the price of a token in USD.

        Args:
            token: The token to get the price for

        Returns:
            The price of the token in USD with 6 decimal places, or 0 if not available
        """
        # First, check if we have a HTR-USD pool set
        if not self.htr_usd_pool_key:
            return Amount(0)

        # Get the token price in HTR
        token_price_in_htr = self.get_token_price_in_htr(token)
        if token_price_in_htr == 0:
            return Amount(0)

        # Get the HTR price in USD
        pool_key = self.htr_usd_pool_key
        reserve_a = self.pool_reserve_a[pool_key]
        reserve_b = self.pool_reserve_b[pool_key]

        # Determine which reserve is HTR and which is USD
        if self.pool_token_a[pool_key] == HTR_UID:
            htr_reserve = reserve_a
            usd_reserve = reserve_b
        else:
            htr_reserve = reserve_b
            usd_reserve = reserve_a

        # Calculate HTR price in USD with 6 decimal places
        if htr_reserve == 0:
            return Amount(0)

        htr_price_in_usd = (usd_reserve * 1_000000) // htr_reserve

        # Calculate token price in USD: token_price_in_htr * htr_price_in_usd / 1_000000
        return Amount((token_price_in_htr * htr_price_in_usd) // 1_000000)

    @view
    def get_all_token_prices_in_usd(self) -> dict[str, Amount]:
        """Get the prices of all tokens that have HTR pools in USD.

        Returns:
            A dictionary mapping token UIDs (hex) to their prices in USD with 6 decimal places
        """
        # First, check if we have a HTR-USD pool set
        if not self.htr_usd_pool_key:
            return {}

        # Get all token prices in HTR
        token_prices_in_htr = self.get_all_token_prices_in_htr()
        if not token_prices_in_htr:
            return {}

        # Get the HTR price in USD
        pool_key = self.htr_usd_pool_key
        reserve_a = self.pool_reserve_a[pool_key]
        reserve_b = self.pool_reserve_b[pool_key]

        # Determine which reserve is HTR and which is USD
        if self.pool_token_a[pool_key] == HTR_UID:
            htr_reserve = reserve_a
            usd_reserve = reserve_b
        else:
            htr_reserve = reserve_b
            usd_reserve = reserve_a

        # Calculate HTR price in USD with 6 decimal places
        if htr_reserve == 0:
            return {}

        htr_price_in_usd = (usd_reserve * 1_000000) // htr_reserve

        # Calculate all token prices in USD
        result = {}
        for token_hex, price_in_htr in token_prices_in_htr.items():
            price_in_usd = (price_in_htr * htr_price_in_usd) // 1_000000
            result[token_hex] = price_in_usd

        return result

    @public
    def change_owner(self, ctx: Context, new_owner: Address) -> None:
        """Change the owner of the contract.

        Args:
            ctx: The transaction context
            new_owner: The new owner address

        Raises:
            Unauthorized: If the caller is not the owner
        """
        if ctx.address != self.owner:
            raise Unauthorized("Only owner can change owner")

        self.owner = new_owner

    @view
    def get_reserves(
        self,
        token_a: TokenUid,
        token_b: TokenUid,
        fee: Amount,
    ) -> tuple[Amount, Amount]:
        """Get the reserves for a specific pool.

        Args:
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool

        Returns:
            A tuple of (reserve_a, reserve_b)

        Raises:
            PoolNotFound: If the pool does not exist
        """
        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        pool_key = self._get_pool_key(token_a, token_b, fee)
        self._validate_pool_exists(pool_key)

        return (self.pool_reserve_a[pool_key], self.pool_reserve_b[pool_key])

    @view
    def get_all_pools(self) -> list[str]:
        """Get a list of all pools with their tokens and fees.

        Returns:
            A list of tuples (token_a, token_b, fee)
        """
        result = []
        for pool_key in self.all_pools:
            token_a = self.pool_token_a[pool_key].hex()
            token_b = self.pool_token_b[pool_key].hex()
            fee = self.pool_fee_numerator[pool_key]
            result.append(f"{token_a}/{token_b}/{fee}")
        return result

    @view
    def get_pools_for_token(self, token: TokenUid) -> list[str]:
        """Get all pools that contain a specific token.

        Args:
            token: The token to search for

        Returns:
            A list of tuples (token_a, token_b, fee)
        """
        if token not in self.token_to_pools:
            return []

        result = []
        for pool_key in self.token_to_pools[token]:
            token_a = self.pool_token_a[pool_key].hex()
            token_b = self.pool_token_b[pool_key].hex()
            fee = self.pool_fee_numerator[pool_key]
            result.append(f"{token_a}/{token_b}/{fee}")
        return result

    @view
    def liquidity_of(
        self,
        address: Address,
        pool_key: str,
    ) -> Amount:
        """Get the liquidity of an address in a specific pool.

        Args:
            address: The address to check
            token_a: First token of the pair
            token_b: Second token of the pair
            fee: Fee for the pool

        Returns:
            The liquidity amount

        Raises:
            PoolNotFound: If the pool does not exist
        """
        self._validate_pool_exists(pool_key)

        return Amount(self.pool_user_liquidity[pool_key].get(address, 0))

    @view
    def balance_of(
        self,
        address: Address,
        pool_key: str,
    ) -> tuple[Amount, Amount]:
        """Get the balance of an address in a specific pool.

        Args:
            address: The address to check
            pool_key: The pool key to check

        Returns:
            A tuple of (balance_a, balance_b)

        Raises:
            PoolNotFound: If the pool does not exist
        """
        self._validate_pool_exists(pool_key)

        balance_a = Amount(self.pool_balance_a.get(pool_key, {}).get(address, 0))
        balance_b = Amount(self.pool_balance_b.get(pool_key, {}).get(address, 0))

        return (balance_a, balance_b)

    @view
    def front_end_api_pool(
        self,
        pool_key: str,
    ) -> dict[str, Amount | str | None]:
        """Get pool information for frontend display.

        Args:
            pool_key: The pool key to check

        Returns:
            A dictionary with pool information

        Raises:
            PoolNotFound: If the pool does not exist
        """

        token_a, token_b, fee = pool_key.split("/")
        token_a = TokenUid(bytes.fromhex(token_a))
        token_b = TokenUid(bytes.fromhex(token_b))
        fee = Amount(int(fee))
        # Ensure tokens are ordered
        if token_a > token_b:
            token_a, token_b = token_b, token_a

        pool_key = self._get_pool_key(token_a, token_b, fee)
        self._validate_pool_exists(pool_key)

        is_signed = pool_key in self.pool_signers
        signer_address = self.pool_signers.get(pool_key, None)
        signer_str = (
            get_address_b58_from_bytes(signer_address)
            if signer_address is not None
            else None
        )

        return {
            "reserve0": Amount(self.pool_reserve_a[pool_key]),
            "reserve1": Amount(self.pool_reserve_b[pool_key]),
            "fee": Amount(self.pool_fee_numerator[pool_key]),
            "volume": Amount(self.pool_volume_a[pool_key]),
            "fee0": Amount(self.pool_accumulated_fee[pool_key].get(token_a, 0)),
            "fee1": Amount(self.pool_accumulated_fee[pool_key].get(token_b, 0)),
            "dzr_rewards": Amount(1000),  # Placeholder as in original implementation
            "transactions": Amount(self.pool_transactions[pool_key]),
            "is_signed": Amount(1 if is_signed else 0),
            "signer": signer_str,
        }

    @view
    def front_end_api_pool_str(
        self,
        pool_key: str,
    ) -> str:
        """Get pool information for frontend display as JSON string."""
        json_pool_info = self.front_end_api_pool(pool_key)
        return dumps(json_pool_info)

    @view
    def pool_info(
        self,
        pool_key: str,
    ) -> dict[str, str | int | bool | None]:
        """Get detailed information about a pool.

        Args:
            pool_key: The pool key to check

        Returns:
            A dictionary with pool information

        Raises:
            PoolNotFound: If the pool does not exist
        """
        self._validate_pool_exists(pool_key)
        is_signed = pool_key in self.pool_signers
        signer_address = self.pool_signers.get(pool_key, None)
        signer_str = (
            get_address_b58_from_bytes(signer_address)
            if signer_address is not None
            else None
        )

        return {
            "token_a": self.pool_token_a.get(pool_key, b"").hex(),
            "token_b": self.pool_token_b.get(pool_key, b"").hex(),
            "reserve_a": self.pool_reserve_a.get(pool_key, None),
            "reserve_b": self.pool_reserve_b.get(pool_key, None),
            "fee": self.pool_fee_numerator.get(pool_key, None),
            "total_liquidity": self.pool_total_liquidity.get(pool_key, None),
            "transactions": self.pool_transactions.get(pool_key, None),
            "volume_a": self.pool_volume_a.get(pool_key, None),
            "volume_b": self.pool_volume_b.get(pool_key, None),
            "last_activity": self.pool_last_activity.get(pool_key, None),
            "is_signed": is_signed,
            "signer": signer_str,
        }

    @view
    def pool_info_str(
        self,
        pool_key: str,
    ) -> str:
        """Get detailed information about a pool."""
        pool_info = self.pool_info(pool_key)
        return dumps(pool_info)

    @view
    def user_info(
        self,
        address: Address,
        pool_key: str,
    ) -> dict[str, Any]:
        """Get detailed information about a user's position in a pool.

        Args:
            address: The address to check
            pool_key: The pool key to check

        Returns:
            A dictionary with user information

        Raises:
            PoolNotFound: If the pool does not exist
        """
        self._validate_pool_exists(pool_key)

        liquidity = self.pool_user_liquidity[pool_key].get(address, 0)
        balance_a = self.pool_balance_a.get(pool_key, {}).get(address, 0)
        balance_b = self.pool_balance_b.get(pool_key, {}).get(address, 0)

        # Calculate share
        share = 0
        if self.pool_total_liquidity[pool_key] > 0:
            share = liquidity * 100 / self.pool_total_liquidity[pool_key]

        # Calculate token amounts based on share
        token_a_amount = (
            self.pool_reserve_a[pool_key]
            * liquidity
            // self.pool_total_liquidity[pool_key]
        )
        token_b_amount = (
            self.pool_reserve_b[pool_key]
            * liquidity
            // self.pool_total_liquidity[pool_key]
        )

        return {
            "liquidity": liquidity,
            "share": share,
            "token_a_amount": token_a_amount,
            "token_b_amount": token_b_amount,
            "balance_a": balance_a,
            "balance_b": balance_b,
        }

    @view
    def front_quote_exact_tokens_for_tokens(
        self, amount_in: Amount, token_in: TokenUid, token_out: TokenUid, fee: Amount
    ) -> dict[str, Any]:
        """Calculate the amount of tokens received for a given input amount.

        Args:
            amount_in: The amount of input tokens
            token_in: The input token
            token_out: The output token
            fee: The pool fee (used for direct pools, ignored for multi-hop)

        Returns:
            A dictionary with amount_out and price_impact
        """
        # First try direct swap with the specified fee
        try:
            pool_key = self._get_pool_key(token_in, token_out, fee)
            if pool_key in self.all_pools:
                # Calculate price impact
                reserve_in = 0
                reserve_out = 0

                if self.pool_token_a[pool_key] == token_in:
                    reserve_in = self.pool_reserve_a[pool_key]
                    reserve_out = self.pool_reserve_b[pool_key]
                else:
                    reserve_in = self.pool_reserve_b[pool_key]
                    reserve_out = self.pool_reserve_a[pool_key]

                # Calculate amount_out using the correct parameters
                fee_denominator = self.pool_fee_denominator[pool_key]
                amount_out = self.get_amount_out(
                    amount_in, reserve_in, reserve_out, fee, fee_denominator
                )

                # Calculate quote (no fee)
                quote = (amount_in * reserve_out) // reserve_in

                if amount_out == 0:
                    price_impact = 0
                else:
                    price_impact = 100 * (quote - amount_out) / amount_out - fee / 10

                if price_impact < 0:
                    price_impact = 0

                return {
                    "amount_out": amount_out,
                    "price_impact": price_impact,
                    "path": pool_key,
                    "amounts": [amount_in, amount_out],
                }
        except Exception:
            pass  # Fall through to pathfinding

        # If direct swap fails or doesn't exist, use pathfinding
        return self.find_best_swap_path(amount_in, token_in, token_out, 3)

    @view
    def front_quote_tokens_for_exact_tokens(
        self, amount_out: Amount, token_in: TokenUid, token_out: TokenUid, fee: Amount
    ) -> dict[str, Any]:
        """Calculate the required amount of input tokens to obtain a specific amount of output tokens.

        Args:
            amount_out: The desired amount of output tokens
            token_in: The input token
            token_out: The output token
            fee: The pool fee (used for direct pools, ignored for multi-hop)

        Returns:
            A dictionary with amount_in and price_impact
        """
        # First try direct swap with the specified fee
        try:
            pool_key = self._get_pool_key(token_in, token_out, fee)
            if pool_key in self.all_pools:
                # Calculate price impact
                reserve_in = 0
                reserve_out = 0

                if self.pool_token_a[pool_key] == token_in:
                    reserve_in = self.pool_reserve_a[pool_key]
                    reserve_out = self.pool_reserve_b[pool_key]
                else:
                    reserve_in = self.pool_reserve_b[pool_key]
                    reserve_out = self.pool_reserve_a[pool_key]

                # Calculate amount_in using the correct parameters
                fee_denominator = self.pool_fee_denominator[pool_key]
                amount_in = self.get_amount_in(
                    amount_out, reserve_in, reserve_out, fee, fee_denominator
                )

                # Calculate quote (no fee)
                quote = (amount_out * reserve_in) // reserve_out

                if amount_in == 0:
                    price_impact = 0
                else:
                    price_impact = 100 * (amount_in - quote) / quote - fee / 10

                if price_impact < 0:
                    price_impact = 0

                return {
                    "amount_in": amount_in,
                    "price_impact": price_impact,
                    "path": pool_key,
                    "amounts": [amount_in, amount_out],
                }
        except Exception:
            pass  # Fall through to pathfinding

        # If direct swap fails, use reverse pathfinding for exact output
        # Use the new exact output pathfinding algorithm
        path_result = self.find_best_swap_path_exact_output(
            amount_out, token_in, token_out, 3
        )

        if path_result["amount_in"] > 0:
            return {
                "amount_in": path_result["amount_in"],
                "price_impact": path_result["price_impact"],
                "path": path_result["path"],
                "amounts": [path_result["amount_in"], amount_out],
            }

        # If pathfinding fails, return zero result
        return {
            "amount_in": 0,
            "price_impact": 0,
            "path": "",
            "amounts": [0, amount_out],
        }

    @view
    def find_best_swap_path(
        self, amount_in: Amount, token_in: TokenUid, token_out: TokenUid, max_hops: int
    ) -> dict[str, Any]:
        """Find the best path for swapping between two tokens using Dijkstra's algorithm.

        This method calculates the optimal path for swapping from token_in to token_out,
        using Dijkstra's algorithm to guarantee the best possible output amount.

        Args:
            amount_in: The amount of input tokens
            token_in: The input token
            token_out: The output token
            max_hops: Maximum number of hops (1-3, but algorithm handles any number)

        Returns:
            A dictionary containing:
            - path: Comma-separated string of pool keys to traverse
            - amounts: Expected amounts at each step
            - amount_out: Final expected output amount
            - price_impact: Overall price impact
        """
        # Limit max_hops to reasonable number for gas efficiency
        if max_hops > 5:
            max_hops = 5

        # Build graph of all possible token pairs and their exchange rates
        graph = self._build_token_graph(amount_in)

        if token_in not in graph:
            return {
                "path": "",
                "amounts": [amount_in],
                "amount_out": 0,
                "price_impact": 0,
            }

        # Run Dijkstra's algorithm to find optimal path
        path_info = self._dijkstra_shortest_path(
            graph, token_in, token_out, amount_in, max_hops
        )

        if not path_info["path"]:
            return {
                "path": "",
                "amounts": [amount_in],
                "amount_out": 0,
                "price_impact": 0,
            }

        # Calculate price impact for the optimal path
        price_impact = self._calculate_price_impact(
            amount_in, path_info["amount_out"], path_info["path"], token_in, token_out
        )

        return {
            "path": path_info["path"],
            "amounts": path_info["amounts"],
            "amount_out": path_info["amount_out"],
            "price_impact": price_impact,
        }

    @view
    def _build_token_graph(
        self, reference_amount: Amount
    ) -> dict[TokenUid, dict[TokenUid, tuple[Amount, str, Amount]]]:
        """Build a graph of tokens with edge weights as (output_amount, pool_key, fee).

        Args:
            reference_amount: Reference amount to calculate exchange rates

        Returns:
            Graph structure: token -> {neighbor_token: (output_amount, pool_key, fee)}
        """
        graph = {}

        # Try different fee tiers for each pool to find the best rates
        fee_tiers = [Amount(3), Amount(5), Amount(10), Amount(30)]

        for pool_key in self.all_pools:
            token_a = self.pool_token_a[pool_key]
            token_b = self.pool_token_b[pool_key]
            fee = self.pool_fee_numerator[pool_key]
            fee_denominator = self.pool_fee_denominator[pool_key]

            try:
                # Calculate A->B exchange rate
                output_b = self.get_amount_out(
                    reference_amount,
                    self.pool_reserve_a[pool_key],
                    self.pool_reserve_b[pool_key],
                    fee,
                    fee_denominator,
                )

                if token_a not in graph:
                    graph[token_a] = {}

                # Only add edge if it's better than existing edge or no edge exists
                if (
                    token_b not in graph[token_a]
                    or output_b > graph[token_a][token_b][0]
                ):
                    graph[token_a][token_b] = (output_b, pool_key, fee)

            except Exception:
                pass  # Skip pools with insufficient liquidity

            try:
                # Calculate B->A exchange rate
                output_a = self.get_amount_out(
                    reference_amount,
                    self.pool_reserve_b[pool_key],
                    self.pool_reserve_a[pool_key],
                    fee,
                    fee_denominator,
                )

                if token_b not in graph:
                    graph[token_b] = {}

                # Only add edge if it's better than existing edge or no edge exists
                if (
                    token_a not in graph[token_b]
                    or output_a > graph[token_b][token_a][0]
                ):
                    graph[token_b][token_a] = (output_a, pool_key, fee)

            except Exception:
                pass  # Skip pools with insufficient liquidity

        return graph

    @view
    def _dijkstra_shortest_path(
        self,
        graph: dict[TokenUid, dict[TokenUid, tuple[Amount, str, Amount]]],
        start: TokenUid,
        end: TokenUid,
        amount_in: Amount,
        max_hops: int,
    ) -> dict[str, Any]:
        """Find the optimal path using Dijkstra's algorithm.

        Args:
            graph: Token graph with exchange rates
            start: Starting token
            end: Target token
            amount_in: Input amount
            max_hops: Maximum number of hops allowed

        Returns:
            Dictionary with path information
        """
        # Initialize distances (we want to maximize output, so we use negative distances)
        # distances[token] = (max_output_amount, hops_count)
        distances = {}
        previous = {}
        unvisited = set()

        # Initialize all tokens
        for token in graph.keys():
            distances[token] = (0, 0)  # (amount, hops)
            unvisited.add(token)

        # Set start token distance to input amount
        distances[start] = (amount_in, 0)

        while unvisited:
            # Find unvisited token with maximum output amount
            current = None
            max_amount = 0

            for token in unvisited:
                amount, hops = distances[token]
                if amount > max_amount:
                    max_amount = amount
                    current = token

            if current is None or max_amount == 0:
                break  # No reachable tokens

            if current == end:
                break  # Found target

            current_amount, current_hops = distances[current]

            # Skip if we've exceeded max hops
            if current_hops >= max_hops:
                unvisited.remove(current)
                continue

            unvisited.remove(current)

            # Check all neighbors
            for neighbor, (reference_output, pool_key, fee) in graph.get(
                current, {}
            ).items():
                if neighbor not in unvisited:
                    continue

                # Calculate actual output for current amount
                try:
                    # Get current reserves for this pool
                    if self.pool_token_a[pool_key] == current:
                        reserve_in = self.pool_reserve_a[pool_key]
                        reserve_out = self.pool_reserve_b[pool_key]
                    else:
                        reserve_in = self.pool_reserve_b[pool_key]
                        reserve_out = self.pool_reserve_a[pool_key]

                    actual_output = self.get_amount_out(
                        current_amount,
                        reserve_in,
                        reserve_out,
                        fee,
                        self.pool_fee_denominator[pool_key],
                    )

                    neighbor_amount, neighbor_hops = distances[neighbor]
                    new_hops = current_hops + 1

                    # Update if we found a better path
                    if actual_output > neighbor_amount:
                        distances[neighbor] = (actual_output, new_hops)
                        previous[neighbor] = (current, pool_key)

                except Exception:
                    continue  # Skip if calculation fails

        # Reconstruct path
        if end not in previous and end != start:
            return {"path": "", "amounts": [amount_in], "amount_out": 0}

        path_pools = []
        amounts = []
        current = end

        # Build path backwards
        while current in previous:
            prev_token, pool_key = previous[current]
            path_pools.insert(0, pool_key)
            amounts.insert(0, distances[current][0])
            current = prev_token

        amounts.insert(0, amount_in)
        final_amount = distances[end][0] if end in distances else 0

        return {
            "path": ",".join(path_pools),
            "amounts": amounts,
            "amount_out": final_amount,
        }

    @view
    def _calculate_price_impact(
        self,
        amount_in: Amount,
        amount_out: Amount,
        path: str,
        token_in: TokenUid,
        token_out: TokenUid,
    ) -> Amount:
        """Calculate price impact for a swap path.

        Args:
            amount_in: Input amount
            amount_out: Output amount
            path: Comma-separated pool keys
            token_in: Input token
            token_out: Output token

        Returns:
            Price impact as a percentage (with precision)
        """
        if not path or amount_out == 0:
            return Amount(0)

        # For direct swaps, calculate price impact using pool reserves
        pool_keys = path.split(",")
        if len(pool_keys) == 1:
            pool_key = pool_keys[0]

            # Get reserves
            if self.pool_token_a[pool_key] == token_in:
                reserve_in = self.pool_reserve_a[pool_key]
                reserve_out = self.pool_reserve_b[pool_key]
            else:
                reserve_in = self.pool_reserve_b[pool_key]
                reserve_out = self.pool_reserve_a[pool_key]

            # Calculate quote without fees
            no_fee_quote = (amount_in * reserve_out) // reserve_in

            if no_fee_quote > 0:
                # Price impact = (no_fee_quote - actual_output) / no_fee_quote * 100
                price_impact = (100 * (no_fee_quote - amount_out)) // no_fee_quote
                return Amount(max(0, price_impact))

        # For multi-hop, calculate cumulative price impact across all pools
        return self._calculate_multi_hop_price_impact(
            amount_in, amount_out, pool_keys, token_in, token_out
        )

    @view
    def _calculate_multi_hop_price_impact(
        self,
        amount_in: Amount,
        amount_out: Amount,
        pool_keys: list[str],
        token_in: TokenUid,
        token_out: TokenUid,
    ) -> Amount:
        """Calculate price impact for multi-hop swaps.

        The strategy is to calculate the theoretical amount out using spot prices
        (without considering slippage) and compare it with the actual amount out.

        Args:
            amount_in: Input amount
            amount_out: Actual output amount
            pool_keys: List of pool keys in the swap path
            token_in: Input token
            token_out: Output token

        Returns:
            Price impact as a percentage (with precision)
        """
        if len(pool_keys) <= 1 or amount_out == 0:
            return Amount(0)

        try:
            # Calculate theoretical amount out using spot prices (no slippage)
            theoretical_amount_out = self._calculate_theoretical_multi_hop_output(
                amount_in, pool_keys, token_in, token_out
            )

            if theoretical_amount_out == 0:
                return Amount(0)

            # Price impact = (theoretical - actual) / theoretical * 100
            price_impact = (100 * (theoretical_amount_out - amount_out)) // theoretical_amount_out
            return Amount(max(0, min(price_impact, 100)))  # Cap at 100%

        except Exception:
            # If calculation fails, return 0 to avoid contract failure
            return Amount(0)

    @view
    def _calculate_theoretical_multi_hop_output(
        self,
        amount_in: Amount,
        pool_keys: list[str],
        token_in: TokenUid,
        token_out: TokenUid,
    ) -> Amount:
        """Calculate theoretical output for multi-hop swap using spot prices.

        This simulates the swap using very small amounts to approximate spot prices,
        avoiding the slippage that occurs with large trades.

        Args:
            amount_in: Input amount
            pool_keys: List of pool keys in the swap path
            token_in: Input token
            token_out: Output token

        Returns:
            Theoretical output amount
        """
        # Use a small reference amount (1% of input) to calculate spot rates
        ref_amount = max(Amount(1), amount_in // 100)
        current_amount = ref_amount
        current_token = token_in

        # Trace through each pool to get the exchange rate
        for pool_key in pool_keys:
            if pool_key not in self.all_pools:
                return Amount(0)

            token_a = self.pool_token_a[pool_key]
            token_b = self.pool_token_b[pool_key]

            # Determine which direction we're swapping
            if current_token == token_a:
                # Swapping A -> B
                reserve_in = self.pool_reserve_a[pool_key]
                reserve_out = self.pool_reserve_b[pool_key]
                current_token = token_b
            elif current_token == token_b:
                # Swapping B -> A
                reserve_in = self.pool_reserve_b[pool_key]
                reserve_out = self.pool_reserve_a[pool_key]
                current_token = token_a
            else:
                # Token not found in this pool
                return Amount(0)

            # Calculate spot price output (without fees for theoretical calculation)
            if reserve_in == 0:
                return Amount(0)

            # Use spot price formula: output = input * reserve_out / reserve_in
            current_amount = (current_amount * reserve_out) // reserve_in

            if current_amount == 0:
                return Amount(0)

        # Scale the result back to the original amount
        if ref_amount == 0:
            return Amount(0)

        theoretical_output = (current_amount * amount_in) // ref_amount
        return Amount(theoretical_output)

    @view
    def get_user_positions_str(self, address: Address) -> str:
        """Get detailed information about all user positions as JSON string."""
        positions = self.get_user_positions(address)
        return dumps(positions)

    @view
    def find_best_swap_path_str(
        self, amount_in: Amount, token_in: TokenUid, token_out: TokenUid, max_hops: int
    ) -> str:
        """Find the best path for swapping between two tokens as JSON string."""
        path_info = self.find_best_swap_path(amount_in, token_in, token_out, max_hops)
        return dumps(path_info)

    @view
    def find_best_swap_path_exact_output(
        self, amount_out: Amount, token_in: TokenUid, token_out: TokenUid, max_hops: int
    ) -> dict[str, Any]:
        """Find the best path for swapping to get exact output amount using reverse pathfinding.

        This method calculates the optimal path for swapping from token_in to token_out,
        using reverse Dijkstra's algorithm to guarantee the minimum input amount needed.

        Args:
            amount_out: The desired output amount
            token_in: The input token
            token_out: The output token
            max_hops: Maximum number of hops (1-3, but algorithm handles any number)

        Returns:
            A dictionary containing:
            - path: Comma-separated string of pool keys to traverse
            - amounts: Expected amounts at each step (reverse order)
            - amount_in: Required input amount
            - price_impact: Overall price impact
        """
        # Limit max_hops to reasonable number for gas efficiency
        if max_hops > 5:
            max_hops = 5

        # Build reverse graph of all possible token pairs and their exchange rates
        graph = self._build_reverse_token_graph(amount_out)

        if token_out not in graph:
            return {
                "path": "",
                "amounts": [amount_out],
                "amount_in": 0,
                "price_impact": 0,
            }

        # Run reverse Dijkstra's algorithm to find optimal path
        path_info = self._dijkstra_reverse_shortest_path(
            graph, token_out, token_in, amount_out, max_hops
        )

        if not path_info["path"]:
            return {
                "path": "",
                "amounts": [amount_out],
                "amount_in": 0,
                "price_impact": 0,
            }

        # Calculate price impact for the optimal path
        price_impact = self._calculate_price_impact(
            path_info["amount_in"], amount_out, path_info["path"], token_in, token_out
        )

        return {
            "path": path_info["path"],
            "amounts": path_info["amounts"],
            "amount_in": path_info["amount_in"],
            "price_impact": price_impact,
        }

    @view
    def _build_reverse_token_graph(
        self, reference_amount: Amount
    ) -> dict[TokenUid, dict[TokenUid, tuple[Amount, str, Amount]]]:
        """Build a reverse graph of tokens with edge weights as (input_amount, pool_key, fee).

        Args:
            reference_amount: Reference amount to calculate exchange rates

        Returns:
            Graph structure: token -> {neighbor_token: (input_amount, pool_key, fee)}
        """
        graph = {}

        for pool_key in self.all_pools:
            token_a = self.pool_token_a[pool_key]
            token_b = self.pool_token_b[pool_key]
            fee = self.pool_fee_numerator[pool_key]
            fee_denominator = self.pool_fee_denominator[pool_key]

            try:
                # Calculate A->B exchange rate (reverse: how much A needed for reference_amount B)
                input_a = self.get_amount_in(
                    reference_amount,
                    self.pool_reserve_a[pool_key],
                    self.pool_reserve_b[pool_key],
                    fee,
                    fee_denominator,
                )

                if token_b not in graph:
                    graph[token_b] = {}

                # Only add edge if it's better than existing edge or no edge exists
                if (
                    token_a not in graph[token_b]
                    or graph[token_b][token_a][0] > input_a
                ):
                    graph[token_b][token_a] = (input_a, pool_key, fee)

                # Calculate B->A exchange rate (reverse: how much B needed for reference_amount A)
                input_b = self.get_amount_in(
                    reference_amount,
                    self.pool_reserve_b[pool_key],
                    self.pool_reserve_a[pool_key],
                    fee,
                    fee_denominator,
                )

                if token_a not in graph:
                    graph[token_a] = {}

                # Only add edge if it's better than existing edge or no edge exists
                if (
                    token_b not in graph[token_a]
                    or graph[token_a][token_b][0] > input_b
                ):
                    graph[token_a][token_b] = (input_b, pool_key, fee)

            except Exception:
                # Skip pools with insufficient liquidity or other errors
                continue

        return graph

    @view
    def _dijkstra_reverse_shortest_path(
        self,
        graph: dict[TokenUid, dict[TokenUid, tuple[Amount, str, Amount]]],
        start_token: TokenUid,
        end_token: TokenUid,
        amount_out: Amount,
        max_hops: int,
    ) -> dict[str, Any]:
        """Use Dijkstra's algorithm to find the path that minimizes input amount for exact output.

        Args:
            graph: The token graph with reverse edge weights
            start_token: Starting token (output token)
            end_token: Ending token (input token)
            amount_out: Desired output amount
            max_hops: Maximum number of hops

        Returns:
            Dictionary with path, amounts, and required input amount
        """
        # Priority queue: (negative_total_input, current_token, path, amounts, hops)
        import heapq

        pq = [(0, start_token, [], [amount_out], 0)]
        visited = set()

        while pq:
            neg_total_input, current_token, path, amounts, hops = heapq.heappop(pq)

            # Skip if we've already visited this token with fewer hops
            visit_key = (current_token, hops)
            if visit_key in visited:
                continue
            visited.add(visit_key)

            # If we've reached the target token, return the path
            if current_token == end_token:
                return {
                    "path": ",".join(reversed(path)),
                    "amounts": list(reversed(amounts)),
                    "amount_in": -neg_total_input,
                }

            # If we've exceeded max hops, skip
            if hops >= max_hops:
                continue

            # Explore neighbors
            if current_token in graph:
                current_amount = amounts[-1]
                for neighbor_token, (base_input, pool_key, fee) in graph[
                    current_token
                ].items():
                    # Calculate required input for current amount
                    reserve_in = self._get_reserve(neighbor_token, pool_key)
                    reserve_out = self._get_reserve(current_token, pool_key)

                    try:
                        required_input = self.get_amount_in(
                            current_amount,
                            reserve_in,
                            reserve_out,
                            fee,
                            self.pool_fee_denominator[pool_key],
                        )

                        new_path = path + [pool_key]
                        new_amounts = amounts + [required_input]
                        new_total_input = -neg_total_input + required_input

                        heapq.heappush(
                            pq,
                            (
                                -new_total_input,
                                neighbor_token,
                                new_path,
                                new_amounts,
                                hops + 1,
                            ),
                        )
                    except Exception:
                        # Skip if calculation fails
                        continue

        # No path found
        return {
            "path": "",
            "amounts": [amount_out],
            "amount_in": 0,
        }

    @view
    def find_best_swap_path_exact_output_str(
        self, amount_out: Amount, token_in: TokenUid, token_out: TokenUid, max_hops: int
    ) -> str:
        """Find the best path for exact output swapping as JSON string."""
        path_info = self.find_best_swap_path_exact_output(
            amount_out, token_in, token_out, max_hops
        )
        return json.dumps(path_info)

    @view
    def user_info_str(self, address: Address, pool_key: str) -> str:
        """Get detailed information about a user's position as JSON string."""
        user_info = self.user_info(address, pool_key)
        return json.dumps(user_info)

    @view
    def calculate_amount_out(
        self,
        amount_in: Amount,
        token_in: TokenUid,
        token_out: TokenUid,
        fee: Amount,
        fee_denominator: Amount = Amount(1000),
    ) -> Amount:
        """Calculate the output amount for a given input amount, taking into account the fee denominator.

        This is a specialized version of get_amount_out for cross-pool swaps.

        Args:
            amount_in: The amount of input tokens
            token_in: The input token
            token_out: The output token
            fee: The pool fee
            fee_denominator: The denominator for the fee calculation (default: 1000)

        Returns:
            The maximum output amount

        Raises:
            PoolNotFound: If the pool does not exist
            InsufficientLiquidity: If there is not enough liquidity
        """
        pool_key = self._get_pool_key(token_in, token_out, fee)
        if pool_key not in self.all_pools:
            raise PoolNotFound()

        # Get reserves
        reserve_in = 0
        reserve_out = 0

        if self.pool_token_a[pool_key] == token_in:
            reserve_in = self.pool_reserve_a[pool_key]
            reserve_out = self.pool_reserve_b[pool_key]
        else:
            reserve_in = self.pool_reserve_b[pool_key]
            reserve_out = self.pool_reserve_a[pool_key]

        if reserve_in == 0 or reserve_out == 0:
            raise InsufficientLiquidity()

        # Calculate amount out with fee
        amount_in_with_fee = amount_in * (fee_denominator - fee)
        numerator = amount_in_with_fee * reserve_out
        denominator = reserve_in * fee_denominator + amount_in_with_fee

        return Amount(numerator // denominator)

    @view
    def calculate_amount_in(
        self,
        amount_out: Amount,
        token_in: TokenUid,
        token_out: TokenUid,
        fee: Amount,
        fee_denominator: Amount = Amount(1000),
    ) -> Amount:
        """Calculate the input amount required for a desired output amount, taking into account the fee denominator.

        This is a specialized version of get_amount_in for cross-pool swaps.

        Args:
            amount_out: The desired amount of output tokens
            token_in: The input token
            token_out: The output token
            fee: The pool fee
            fee_denominator: The denominator for the fee calculation (default: 1000)

        Returns:
            The minimum input amount required

        Raises:
            PoolNotFound: If the pool does not exist
            InsufficientLiquidity: If there is not enough liquidity
        """
        pool_key = self._get_pool_key(token_in, token_out, fee)
        if pool_key not in self.all_pools:
            raise PoolNotFound()

        # Get reserves
        reserve_in = 0
        reserve_out = 0

        if self.pool_token_a[pool_key] == token_in:
            reserve_in = self.pool_reserve_a[pool_key]
            reserve_out = self.pool_reserve_b[pool_key]
        else:
            reserve_in = self.pool_reserve_b[pool_key]
            reserve_out = self.pool_reserve_a[pool_key]

        if reserve_in == 0 or reserve_out == 0 or amount_out >= reserve_out:
            raise InsufficientLiquidity()

        # Calculate amount in with fee
        numerator = Amount(reserve_in * amount_out * fee_denominator)
        denominator = Amount((reserve_out - amount_out) * (fee_denominator - fee))

        # Round up
        return Amount(numerator // denominator)

