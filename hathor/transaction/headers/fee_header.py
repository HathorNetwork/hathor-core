# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

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
