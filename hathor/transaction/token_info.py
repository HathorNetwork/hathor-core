from __future__ import annotations

from enum import IntEnum
from typing import NamedTuple


class TokenInfoVersion(IntEnum):
    DEPOSIT = 1
    FEE = 2


# used when (de)serializing token information
class TokenInfo(NamedTuple):
    amount: int
    can_mint: bool
    can_melt: bool
    version: TokenInfoVersion | None

    @classmethod
    def create_empty(cls, version: TokenInfoVersion | None = None, is_new_token: bool = False) -> TokenInfo:
        return TokenInfo(
            amount=0,
            can_mint=is_new_token,
            can_melt=is_new_token,
            version=version,
        )
