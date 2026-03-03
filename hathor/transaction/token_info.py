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
from typing import TYPE_CHECKING, Any

from hathor.types import TokenUid

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.nanocontracts.storage import NCBlockStorage
    from hathor.transaction.storage import TransactionStorage


class TokenVersion(IntEnum):
    NATIVE = 0
    DEPOSIT = 1
    FEE = 2


# used when (de)serializing token information
@dataclass(slots=True, kw_only=True)
class TokenInfo:
    version: TokenVersion | None
    amount: int = 0
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
    token_version: TokenVersion

    def __post_init__(self) -> None:
        assert isinstance(self.token_version, TokenVersion)


class TokenInfoDict(dict[TokenUid, TokenInfo]):
    __slots__ = ('fees_from_fee_header',)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fees_from_fee_header: int = 0

    def calculate_fee(self, settings: 'HathorSettings', *, shielded_fee: int = 0) -> int:
        """
         Calculate the total fee based on the number of chargeable
         outputs and inputs for each token in the transaction.

         The Transaction.get_complete_token_info() should be called before calculating the fee.

         The fee is determined using the following rules:
         - If a token has one or more chargeable outputs, the fee is calculated
           as `chargeable_outputs * settings.FEE_PER_OUTPUT`.
         - If a token has zero chargeable outputs but one or more chargeable inputs,
           a flat fee of `settings.FEE_PER_OUTPUT` is applied.
         - An additional shielded_fee is added for shielded outputs.

         Args:
             settings (HathorSettings): The configuration object containing fee-related
                 parameters, such as `FEE_PER_OUTPUT`.
             shielded_fee: Additional fee for shielded outputs (default 0).

         Returns:
             int: The total transaction fee
         """
        fee = shielded_fee

        for token_uid, token_info in self.items():
            if token_info.chargeable_outputs > 0:
                fee += token_info.chargeable_outputs * settings.FEE_PER_OUTPUT
            else:
                if token_info.chargeable_inputs > 0:
                    fee += settings.FEE_PER_OUTPUT
        return fee


def get_token_version(
    tx_storage: 'TransactionStorage',
    nc_block_storage: 'NCBlockStorage',
    token_uid: TokenUid
) -> TokenVersion | None:
    """
    Get the token version for a given token uid.
    It searches first in the tx storage and then in the block storage.
    """
    from hathor.conf.settings import HATHOR_TOKEN_UID
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
