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

from hathor import Blueprint, Context, NCDepositAction, NCFail, NCWithdrawalAction, TokenUid, export, public, view


@export
class SwapDemo(Blueprint):
    """Blueprint to execute swaps between tokens.
    This blueprint is here just as a reference for blueprint developers, not for real use.
    """

    # TokenA identifier and quantity multiplier.
    token_a: TokenUid
    multiplier_a: int

    # TokenB identifier and quantity multiplier.
    token_b: TokenUid
    multiplier_b: int

    # Count number of swaps executed.
    swaps_counter: int

    @public(allow_deposit=True)
    def initialize(
        self,
        ctx: Context,
        token_a: TokenUid,
        token_b: TokenUid,
        multiplier_a: int,
        multiplier_b: int
    ) -> None:
        """Initialize the contract."""

        if token_a == token_b:
            raise NCFail

        if set(ctx.actions.keys()) != {token_a, token_b}:
            raise InvalidTokens

        self.token_a = token_a
        self.token_b = token_b
        self.multiplier_a = multiplier_a
        self.multiplier_b = multiplier_b
        self.swaps_counter = 0

    @public(allow_deposit=True, allow_withdrawal=True)
    def swap(self, ctx: Context) -> None:
        """Execute a token swap."""

        if set(ctx.actions.keys()) != {self.token_a, self.token_b}:
            raise InvalidTokens

        action_a = ctx.get_single_action(self.token_a)
        action_b = ctx.get_single_action(self.token_b)

        if not (
            (isinstance(action_a, NCDepositAction) and isinstance(action_b, NCWithdrawalAction))
            or (isinstance(action_a, NCWithdrawalAction) and isinstance(action_b, NCDepositAction))
        ):
            raise InvalidActions

        if not self.is_ratio_valid(action_a.amount, action_b.amount):
            raise InvalidRatio

        # All good! Let's accept the transaction.
        self.swaps_counter += 1

    @view
    def is_ratio_valid(self, qty_a: int, qty_b: int) -> bool:
        """Check if the swap quantities are valid."""
        return (self.multiplier_a * qty_a == self.multiplier_b * qty_b)


class InvalidTokens(NCFail):
    pass


class InvalidActions(NCFail):
    pass


class InvalidRatio(NCFail):
    pass
