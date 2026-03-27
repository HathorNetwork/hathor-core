# Copyright 2026 Hathor Labs
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

from __future__ import annotations

from typing import TYPE_CHECKING

from hathorlib.exceptions import InvalidFeeAmount, TransactionDataError
from hathorlib.utils import clean_token_string

if TYPE_CHECKING:
    from hathorlib.conf.settings import HathorSettings


def validate_token_name_and_symbol(settings: HathorSettings,
                                   token_name: str,
                                   token_symbol: str) -> None:
    """Validate token_name and token_symbol before creating a new token."""
    name_len = len(token_name)
    symbol_len = len(token_symbol)
    if name_len == 0 or name_len > settings.MAX_LENGTH_TOKEN_NAME:
        raise TransactionDataError('Invalid token name length ({})'.format(name_len))
    if symbol_len == 0 or symbol_len > settings.MAX_LENGTH_TOKEN_SYMBOL:
        raise TransactionDataError('Invalid token symbol length ({})'.format(symbol_len))

    # Can't create token with hathor name or symbol
    if clean_token_string(token_name) == clean_token_string(settings.HATHOR_TOKEN_NAME):
        raise TransactionDataError('Invalid token name ({})'.format(token_name))
    if clean_token_string(token_symbol) == clean_token_string(settings.HATHOR_TOKEN_SYMBOL):
        raise TransactionDataError('Invalid token symbol ({})'.format(token_symbol))


def validate_fee_amount(settings: HathorSettings, token_uid: bytes, amount: int) -> None:
    """Validate the fee amount."""
    if amount <= 0:
        raise InvalidFeeAmount(f'fees should be a positive integer, got {amount}')

    if token_uid != settings.HATHOR_TOKEN_UID and amount % settings.FEE_DIVISOR != 0:
        raise InvalidFeeAmount(f'fees using deposit custom tokens should be a multiple of {settings.FEE_DIVISOR}, '
                               f'got {amount}')
