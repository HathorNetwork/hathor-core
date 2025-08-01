# Copyright 2021 Hathor Labs
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
