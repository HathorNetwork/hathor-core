# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hathor.types import TokenUid
from hathorlib.conf.settings import HATHOR_TOKEN_UID
from hathorlib.nanocontracts.runner.token_fees import FeeCharge
from hathorlib.token_amount import SignedAmount, UnsignedAmount
from hathorlib.token_info import TokenDescription, TokenVersion  # noqa: F401

if TYPE_CHECKING:
    from hathor.nanocontracts.storage import NCBlockStorage
    from hathor.transaction.storage import TransactionStorage


# used when (de)serializing token information
@dataclass(slots=True, kw_only=True)
class TokenInfo:
    version: TokenVersion | None
    amount: SignedAmount = field(default_factory=SignedAmount)
    can_mint: bool = False
    can_melt: bool = False
    # count of non-authority outputs that is used to calculate the fee
    chargeable_outputs: int = 0
    # count of non-authority inputs that is used to calculate the fee
    chargeable_inputs: int = 0

    def has_been_melted(self) -> bool:
        """
        Check if this token has been melted.
        A token is considered melted if its amount is negative.
        """
        return self.amount < SignedAmount(0)

    def has_been_minted(self) -> bool:
        """
        Check if this token has been minted.
        A token is considered minted if its amount is positive.
        """
        return self.amount > SignedAmount(0)


class TokenInfoDict(dict[TokenUid, TokenInfo]):
    __slots__ = ('header_fee',)

    def __init__(self) -> None:
        super().__init__()
        # The charge paying the header fee, aggregated by `Transaction._update_token_info_from_fees`.
        # It is None while some fee token's version is unresolved (the token is created by the tx's
        # own nano execution), in which case fee checks are deferred to post-execution verification.
        self.header_fee: FeeCharge | None = None

    def calculate_fee(self) -> UnsignedAmount:
        """
        Calculate the total fee based on the number of chargeable
        outputs and inputs for each token in the transaction.

        The Transaction.get_complete_token_info() should be called before calculating the fee.

        Each token is charged a number of units, determined using the following rules:
        - If a token has one or more chargeable outputs, it's charged one unit per chargeable output.
        - If a token has zero chargeable outputs but one or more chargeable inputs, it's charged a flat single unit.

        The price of a unit is set by the fee policy in `header_fee`, that is, by the token paying the fee.
        """
        units = 0

        for token_uid, token_info in self.items():
            if token_info.chargeable_outputs > 0:
                units += token_info.chargeable_outputs
            else:
                if token_info.chargeable_inputs > 0:
                    units += 1

        assert self.header_fee is not None, 'calculate_fee is only valid after header_fee has been aggregated'
        fee_per_unit = self.header_fee.policy.get_fee_based_tokens()
        return UnsignedAmount.from_v2(units * fee_per_unit.normalized())


def get_token_version(
    tx_storage: 'TransactionStorage',
    nc_block_storage: 'NCBlockStorage',
    token_uid: TokenUid
) -> TokenVersion | None:
    """
    Get the token version for a given token uid.
    It searches first in the tx storage and then in the block storage.
    """
    if token_uid == HATHOR_TOKEN_UID:
        return TokenVersion.NATIVE
    from hathor.transaction.storage.exceptions import TransactionDoesNotExist
    try:
        token_creation_tx = tx_storage.get_token_creation_transaction(token_uid)
        return token_creation_tx.token_version
    except TransactionDoesNotExist:
        from hathor.nanocontracts.types import TokenUid
        if nc_block_storage.has_token(TokenUid(token_uid)):
            return nc_block_storage.get_token_description(TokenUid(token_uid)).token_version
    return None
