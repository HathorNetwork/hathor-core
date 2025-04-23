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

from hathor.conf.settings import HathorSettings
from hathor.transaction.token_info import TokenInfo, TokenInfoVersion
from hathor.transaction.util import get_token_amount_from_htr, get_withdraw_amount
from hathor.types import TokenUid


def calculate_fee(settings: HathorSettings, token_dict: dict[TokenUid, TokenInfo]) -> int:
    """Calculate the fee for this transaction.

    The fee is calculated based on fee tokens outputs. It sums up all tokens with TokenInfoVersion.FEE value.

    :return: The total fee in HTR
    :rtype: int
    """
    fee = 0

    for token_uid, token_info in token_dict.items():
        if token_uid is settings.HATHOR_TOKEN_UID or token_info.version is TokenInfoVersion.DEPOSIT:
            continue

        chargeable_outputs = [output for output in token_info.outputs if not output.is_token_authority()]
        chargeable_spent_outputs = [output for output in token_info.spent_outputs if not output.is_token_authority()]

        # is melting fee tokens without an output
        if len(chargeable_spent_outputs) > 0 and len(chargeable_outputs) == 0:
            fee += 1 * settings.FEE_PER_OUTPUT

        fee += len(chargeable_outputs) * settings.FEE_PER_OUTPUT
    return fee


def should_charge_fee(settings: HathorSettings, token_dict: dict[TokenUid, TokenInfo]) -> bool:
    """Check if this transaction should charge a fee.

    A transaction should charge a fee if it has at least one token with FEE version
    """
    if settings.FEE_FEATURE_FLAG is False:
        return False

    # Check if any token in the transaction has FEE version
    for token_uid, token_info in token_dict.items():
        if token_info.version is TokenInfoVersion.FEE:
            return True
    return False


def collect_fee(settings: HathorSettings, fee: int, token_dict: dict[TokenUid, TokenInfo]) -> int:
    """
    Check each the tokens amount and collect the fee that should be paid.
    It changes the token_dict in place with the new amount from the affected tokens.
    """
    assert fee >= 0
    collected_fee = 0
    remaining_fee = fee

    # Check fee payment
    for token_uid, token_info in token_dict.items():
        if remaining_fee == 0:
            return collected_fee

        if token_info.amount == 0:
            # this token doesn't have a valid amount to pay, move to the next
            pass
        # the input wasn't spent, start charging the fee
        elif token_info.amount < 0:
            value_to_pay = 0
            token_amount = token_info.amount
            if token_uid == settings.HATHOR_TOKEN_UID:
                # the amount is a negative value, so we sum the paid fee in order to reduce the available value
                # limit the amount to the fee
                value_to_pay = min(abs(token_amount), remaining_fee)
                token_amount += value_to_pay
            elif token_info.version == TokenInfoVersion.DEPOSIT:
                token_htr_value = get_withdraw_amount(settings, token_amount)
                value_to_pay = min(token_htr_value, remaining_fee)
                token_amount += get_token_amount_from_htr(settings, value_to_pay)

            token_dict[token_uid] = TokenInfo(token_amount, token_info.can_mint, token_info.can_melt,
                                              token_info.version, token_info.spent_outputs, token_info.outputs)
            collected_fee += value_to_pay
            remaining_fee -= value_to_pay

    return collected_fee
