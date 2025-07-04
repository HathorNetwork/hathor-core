from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class TokenInfoVersion(IntEnum):
    DEPOSIT = 1
    FEE = 2


# used when (de)serializing token information
@dataclass(slots=True, kw_only=True)
class TokenInfo:
    amount: int
    can_mint: bool
    can_melt: bool
    version: TokenInfoVersion | None

    @classmethod
    def get_default(cls, version: TokenInfoVersion | None = TokenInfoVersion.DEPOSIT,
                    is_new_token: bool = False) -> TokenInfo:
        """
        Create default deposit token info with zero amount and optional mint/melt permissions.
        """

        return TokenInfo(
            amount=0,
            can_mint=is_new_token,
            can_melt=is_new_token,
            version=version,
        )

    @classmethod
    def get_htr_default(cls):
        """Create a default token info for HTR"""
        return TokenInfo(
            amount=0,
            can_mint=False,
            can_melt=False,
            version=None,
        )
