# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing_extensions import assert_never

from hathorlib.conf.settings import HATHOR_TOKEN_UID, HathorSettings
from hathorlib.nanocontracts.exception import NCInvalidFeePaymentToken
from hathorlib.token_amount import SignedAmount, UnsignedAmount
from hathorlib.token_info import TokenDescription, TokenVersion
from hathorlib.utils import get_deposit_token_deposit_amount, get_deposit_token_withdraw_amount


def calculate_mint_fee(
    *,
    settings: HathorSettings,
    token_version: TokenVersion,
    amount: UnsignedAmount,
    fee_payment_token: TokenDescription,
) -> SignedAmount:
    """Calculate the fee for a mint operation."""
    match token_version:
        case TokenVersion.NATIVE:
            raise AssertionError
        case TokenVersion.DEPOSIT:
            _validate_deposit_based_payment_token(fee_payment_token)
            return -get_deposit_token_deposit_amount(settings, amount).to_signed()
        case TokenVersion.FEE:
            _validate_fee_based_payment_token(fee_payment_token)
            return -_calculate_unit_fee_token_fee(settings, fee_payment_token).to_signed()
        case _:  # pragma: no cover
            assert_never(token_version)


def calculate_melt_fee(
    *,
    settings: HathorSettings,
    token_version: TokenVersion,
    amount: UnsignedAmount,
    fee_payment_token: TokenDescription,
) -> SignedAmount:
    """Calculate the fee for a melt operation."""
    match token_version:
        case TokenVersion.NATIVE:
            raise AssertionError
        case TokenVersion.DEPOSIT:
            _validate_deposit_based_payment_token(fee_payment_token)
            return +get_deposit_token_withdraw_amount(settings, amount).to_signed()
        case TokenVersion.FEE:
            _validate_fee_based_payment_token(fee_payment_token)
            return -_calculate_unit_fee_token_fee(settings, fee_payment_token).to_signed()
        case _:  # pragma: no cover
            assert_never(token_version)


def _validate_deposit_based_payment_token(fee_payment_token: TokenDescription) -> None:
    """Validate the token used to pay the fee of a deposit-based token operation."""
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


def _calculate_unit_fee_token_fee(settings: HathorSettings, fee_payment_token: TokenDescription) -> UnsignedAmount:
    """Calculate the fee for handling a fee-based token"""
    if fee_payment_token.token_id == HATHOR_TOKEN_UID:
        return UnsignedAmount(settings.FEE_PER_OUTPUT_V1)
    numerator = settings.FEE_PER_OUTPUT_V1 * settings.TOKEN_DEPOSIT_PERCENTAGE_DENOMINATOR
    assert numerator % settings.TOKEN_DEPOSIT_PERCENTAGE_NUMERATOR == 0
    return UnsignedAmount(numerator // settings.TOKEN_DEPOSIT_PERCENTAGE_NUMERATOR)
