# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from typing_extensions import assert_never

from hathorlib.conf.fee_policy import FeePolicy, FeePolicyPerToken, FeePolicyVersion
from hathorlib.conf.settings import HATHOR_TOKEN_UID, HathorSettings
from hathorlib.exceptions import InvalidFeePaymentToken
from hathorlib.nanocontracts.exception import NCInvalidFeePaymentToken
from hathorlib.token_amount import SignedAmount, UnsignedAmount
from hathorlib.token_info import TokenDescription, TokenVersion
from hathorlib.utils import get_deposit_token_deposit_amount, get_deposit_token_withdraw_amount


def calculate_mint_fee(
    *,
    settings: HathorSettings,
    fee_policy_version: FeePolicyVersion,
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
            fee_policies = settings.get_fee_policies(fee_policy_version)
            _validate_fee_based_payment_token(fee_policies, fee_payment_token)
            return -_calculate_unit_fee_token_fee(settings, fee_policies, fee_payment_token).to_signed()
        case _:  # pragma: no cover
            assert_never(token_version)


def calculate_melt_fee(
    *,
    settings: HathorSettings,
    fee_policy_version: FeePolicyVersion,
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
            fee_policies = settings.get_fee_policies(fee_policy_version)
            _validate_fee_based_payment_token(fee_policies, fee_payment_token)
            return -_calculate_unit_fee_token_fee(settings, fee_policies, fee_payment_token).to_signed()
        case _:  # pragma: no cover
            assert_never(token_version)


def _validate_deposit_based_payment_token(fee_payment_token: TokenDescription) -> None:
    """Validate the token used to pay the fee of a deposit-based token operation."""
    if fee_payment_token.token_id != HATHOR_TOKEN_UID:
        raise NCInvalidFeePaymentToken('Only HTR is allowed to be used with deposit based token syscalls')


def _validate_fee_based_payment_token(fee_policies: FeePolicyPerToken, fee_payment_token: TokenDescription) -> None:
    """Validate the token used to pay the fee of a fee-based token operation.

    HTR, deposit-based tokens, and tokens listed in the active fee policy can pay; other fee-based tokens cannot.
    """
    match fee_payment_token.token_version:
        case TokenVersion.FEE:
            if fee_payment_token.token_id not in fee_policies:
                raise NCInvalidFeePaymentToken(f'cannot pay fees with token {fee_payment_token.token_id.hex()}')
        case TokenVersion.DEPOSIT | TokenVersion.NATIVE:
            pass
        case _:  # pragma: no cover
            assert_never(fee_payment_token.token_version)


def _calculate_unit_fee_token_fee(
    settings: HathorSettings,
    fee_policies: FeePolicyPerToken,
    fee_payment_token: TokenDescription,
) -> UnsignedAmount:
    """Calculate the fee for handling a fee-based token"""
    if fee_payment_token.token_id in fee_policies:
        return fee_policies[fee_payment_token.token_id].get_fee_based_tokens()
    htr_unit_fee = fee_policies[HATHOR_TOKEN_UID].get_fee_based_tokens()
    numerator = htr_unit_fee.normalized() * settings.TOKEN_DEPOSIT_PERCENTAGE_DENOMINATOR
    assert numerator % settings.TOKEN_DEPOSIT_PERCENTAGE_NUMERATOR == 0
    return UnsignedAmount.from_v2(numerator // settings.TOKEN_DEPOSIT_PERCENTAGE_NUMERATOR)


@dataclass(slots=True, frozen=True, kw_only=True)
class FeeCharge:
    """A single aggregated fee payment: the token paying the fee, its policy, and the total amount."""
    token_uid: bytes
    policy: FeePolicy
    amount: UnsignedAmount


def aggregate_fee_charges(
    *,
    settings: HathorSettings,
    fee_policy_version: FeePolicyVersion,
    charges: Iterable[tuple[bytes, TokenVersion, UnsignedAmount]],
) -> FeeCharge:
    """Validate and aggregate fee payments in a single pass.

    Each fee entry is a `(token_uid, token_version, amount)` tuple; entries for the same token are summed.
    Return a `FeeCharge` with the token paying the fee, its policy, and the total amount.
    """
    fee_policies = settings.get_fee_policies(fee_policy_version)
    htr_policy = settings.get_htr_policy(fee_policy_version)

    amounts: dict[tuple[bytes, FeePolicy], UnsignedAmount] = defaultdict(UnsignedAmount.zero)

    for token_uid, token_version, amount in charges:
        if fee_policy := fee_policies.get(token_uid):
            # Policy tokens charge their own amount.
            amounts[(token_uid, fee_policy)] += amount
        elif token_version == TokenVersion.DEPOSIT:
            # Deposit-based tokens are converted to HTR.
            amounts[(HATHOR_TOKEN_UID, htr_policy)] += get_deposit_token_withdraw_amount(settings, amount)
        else:
            raise InvalidFeePaymentToken(f'cannot pay fees with token {token_uid.hex()}')

    if len(amounts) == 0:
        return FeeCharge(token_uid=HATHOR_TOKEN_UID, policy=htr_policy, amount=UnsignedAmount.zero())

    if len(amounts) != 1:
        raise InvalidFeePaymentToken(
            'fee payments must either use a combination of HTR and deposit-based tokens, or a single stablecoin'
        )

    (token_uid, fee_policy), amount = next(iter(amounts.items()))
    return FeeCharge(token_uid=token_uid, policy=fee_policy, amount=amount)
