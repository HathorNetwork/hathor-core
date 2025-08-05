from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

from hathor.types import TokenUid

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings


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


class TokenInfoDict(dict[TokenUid, TokenInfo]):
    __slots__ = ('chargeable_outputs', 'chargeable_spent_outputs')

    def __init__(self):
        super().__init__()
        self.chargeable_outputs = 0
        self.chargeable_spent_outputs = 0

    def calculate_fee(self, settings: 'HathorSettings') -> int:
        fee = 0
        if self.chargeable_spent_outputs > 0 and self.chargeable_outputs == 0:
            fee += settings.FEE_PER_OUTPUT

        fee += self.chargeable_outputs * settings.FEE_PER_OUTPUT
        return fee
