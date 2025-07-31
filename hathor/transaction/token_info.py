from dataclasses import dataclass
from enum import IntEnum


class TokenVersion(IntEnum):
    NATIVE = 0
    DEPOSIT = 1
    FEE = 2


# used when (de)serializing token information
@dataclass(slots=True, kw_only=True)
class TokenInfo:
    amount: int
    can_mint: bool
    can_melt: bool
    version: TokenVersion

    @classmethod
    def get_default(cls,
                    version: TokenVersion = TokenVersion.NATIVE,
                    can_mint: bool = False,
                    can_melt: bool = False) -> 'TokenInfo':
        """
        Create default deposit token info with zero amount and optional mint/melt permissions.
        """

        return TokenInfo(
            amount=0,
            can_mint=can_mint,
            can_melt=can_melt,
            version=version,
        )

    @classmethod
    def get_htr_default(cls):
        """Create a default token info for HTR"""
        return TokenInfo(
            amount=0,
            can_mint=False,
            can_melt=False,
            version=TokenVersion.NATIVE,
        )


@dataclass(slots=True, frozen=True, kw_only=True)
class TokenDescription:
    token_id: bytes
    token_name: str
    token_symbol: str
