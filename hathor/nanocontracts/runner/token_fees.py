#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from typing_extensions import assert_never

from hathor.conf.settings import HathorSettings
from hathor.nanocontracts.exception import NCInvalidFeePaymentToken
from hathor.transaction.token_info import TokenDescription, TokenVersion
from hathor.transaction.util import get_deposit_token_deposit_amount, get_deposit_token_withdraw_amount


def calculate_mint_fee(
    *,
    settings: HathorSettings,
    token_version: TokenVersion,
    amount: int,
    fee_payment_token: TokenDescription,
) -> int:
    """Calculate the fee for a mint operation."""
    match token_version:
        case TokenVersion.NATIVE:
            raise AssertionError
        case TokenVersion.DEPOSIT:
            _validate_deposit_based_payment_token(fee_payment_token)
            return -get_deposit_token_deposit_amount(settings, amount)
        case TokenVersion.FEE:
            _validate_fee_based_payment_token(fee_payment_token)
            return -_calculate_unit_fee_token_fee(settings, fee_payment_token)
        case _:  # pragma: no cover
            assert_never(token_version)


def calculate_melt_fee(
    *,
    settings: HathorSettings,
    token_version: TokenVersion,
    amount: int,
    fee_payment_token: TokenDescription,
) -> int:
    """Calculate the fee for a melt operation."""
    match token_version:
        case TokenVersion.NATIVE:
            raise AssertionError
        case TokenVersion.DEPOSIT:
            _validate_deposit_based_payment_token(fee_payment_token)
            return +get_deposit_token_withdraw_amount(settings, amount)
        case TokenVersion.FEE:
            _validate_fee_based_payment_token(fee_payment_token)
            return -_calculate_unit_fee_token_fee(settings, fee_payment_token)
        case _:  # pragma: no cover
            assert_never(token_version)


def _validate_deposit_based_payment_token(fee_payment_token: TokenDescription) -> None:
    """Validate the token used to pay the fee of a deposit-based token operation."""
    from hathor import HATHOR_TOKEN_UID
    if fee_payment_token.token_id != HATHOR_TOKEN_UID:
        raise NCInvalidFeePaymentToken('Only HTR is allowed to be used with deposit based token syscalls')


def _validate_fee_based_payment_token(fee_payment_token: TokenDescription) -> None:
    """Validate the token used to pay the fee of a fee-based token operation."""
    match fee_payment_token.token_version:
        case TokenVersion.FEE:
            raise NCInvalidFeePaymentToken("fee-based tokens aren't allowed for paying fees")
        case TokenVersion.DEPOSIT | TokenVersion.NATIVE:
            pass
        case _:  # pragma: no cover
            assert_never(fee_payment_token.token_version)


def _calculate_unit_fee_token_fee(settings: HathorSettings, fee_payment_token: TokenDescription) -> int:
    """Calculate the fee for handling a fee-based token"""
    from hathor import HATHOR_TOKEN_UID
    if fee_payment_token.token_id == HATHOR_TOKEN_UID:
        return settings.FEE_PER_OUTPUT
    return int(settings.FEE_PER_OUTPUT / settings.TOKEN_DEPOSIT_PERCENTAGE)
