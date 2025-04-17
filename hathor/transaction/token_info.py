from __future__ import annotations

from enum import IntEnum
from typing import NamedTuple

from hathor.transaction import TxOutput


class TokenInfoVersion(IntEnum):
    DEPOSIT = 1
    FEE = 2


# used when (de)serializing token information
class TokenInfo(NamedTuple):
    amount: int
    can_mint: bool
    can_melt: bool
    version: TokenInfoVersion | None
    spent_outputs: list[TxOutput]
    outputs: list[TxOutput]
