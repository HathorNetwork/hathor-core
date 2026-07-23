# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from hathor.transaction.util import get_deposit_token_withdraw_amount
from hathor.types import TokenUid
from hathorlib.token_amount import UnsignedAmount

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction.transaction import Transaction


@dataclass(slots=True, kw_only=True, frozen=True)
class FeeHeaderEntry:
    token_index: int
    amount: UnsignedAmount


@dataclass(slots=True, kw_only=True, frozen=True)
class FeeEntry:
    token_uid: TokenUid
    amount: UnsignedAmount


@dataclass(slots=True, kw_only=True)
class FeeHeader:
    # transaction that contains the fee header
    tx: 'Transaction'
    # list of tokens and amounts that will be used to pay fees in the transaction
    fees: list[FeeHeaderEntry]
    settings: HathorSettings

    def __init__(self, settings: HathorSettings, tx: 'Transaction', fees: list[FeeHeaderEntry]):
        self.tx = tx
        self.fees = fees
        self.settings = settings

    def get_fees(self) -> list[FeeEntry]:
        return [
            FeeEntry(
                token_uid=self.tx.get_token_uid(fee.token_index),
                amount=fee.amount
            )
            for fee in self.fees
        ]

    def total_fee_amount(self) -> UnsignedAmount:
        """Sum fees amounts in this header and return as HTR"""
        total_fee = 0
        for fee in self.get_fees():
            if fee.token_uid == self.settings.HATHOR_TOKEN_UID:
                total_fee += fee.amount
            else:
                total_fee += get_deposit_token_withdraw_amount(self.settings, fee.amount)
        return total_fee
