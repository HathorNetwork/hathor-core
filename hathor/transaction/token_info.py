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
    # count of non-authority outputs that is used to calculate the fee
    chargeable_outputs: int = 0
    # count of non-authority inputs that is used to calculate the fee
    chargeable_inputs: int = 0

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

    def has_been_melted(self) -> bool:
        """
        Check if this token has been melted.
        A token is considered melted if its amount is negative.
        """
        return self.amount < 0

    def has_been_minted(self) -> bool:
        """
        Check if this token has been minted.
        A token is considered minted if its amount is positive.
        """
        return self.amount > 0


@dataclass(slots=True, frozen=True, kw_only=True)
class TokenDescription:
    token_id: bytes
    token_name: str
    token_symbol: str


class TokenInfoDict(dict[TokenUid, TokenInfo]):
    def calculate_fee(self, settings: 'HathorSettings') -> int:
        """
         Calculate the total fee based on the number of chargeable
         outputs and inputs for each token in the transaction.

         The Transaction.get_complete_token_info() should be called before calculating the fee.

         The fee is determined using the following rules:
         - If a token has one or more chargeable outputs, the fee is calculated
           as `chargeable_outputs * settings.FEE_PER_OUTPUT`.
         - If a token has zero chargeable outputs but one or more chargeable inputs,
           a flat fee of `settings.FEE_PER_OUTPUT` is applied.

         Args:
             settings (HathorSettings): The configuration object containing fee-related
                 parameters, such as `FEE_PER_OUTPUT`.

         Returns:
             int: The total transaction fee
         """
        fee = 0

        for token_uid, token_info in self.items():
            if token_info.chargeable_outputs > 0:
                fee += token_info.chargeable_outputs * settings.FEE_PER_OUTPUT
            else:
                if token_info.chargeable_inputs > 0:
                    fee += settings.FEE_PER_OUTPUT
        return fee
