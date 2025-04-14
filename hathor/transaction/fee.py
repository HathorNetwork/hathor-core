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
from hathor.transaction.transaction import TokenInfo, TokenInfoVersion
from hathor.transaction.util import get_deposit_amount, get_withdraw_amount
from hathor.types import TokenUid


def calculate_fee(settings: HathorSettings, token_dict: dict[TokenUid, TokenInfo]) -> int:
    """Calculate the fee for this transaction.

    The fee is calculated based on fee tokens outputs. It sums up all tokens with FEE version.

    :return: The total fee in HTR
    :rtype: int
    """
    fee = 0

    for token_uid, token_info in token_dict.items():
        if token_uid is settings.HATHOR_TOKEN_UID or token_info.version is TokenInfoVersion.DEPOSIT:
            continue

        chargeable_outputs = [o for o in token_info.outputs if not o.is_token_authority()]

        # is melting fee tokens without an output
        if len(token_info.inputs) > 0 and len(chargeable_outputs) == 0:
            fee += 1

        fee += len(chargeable_outputs)
    return fee


def should_charge_fee(settings: HathorSettings, token_dict: dict[TokenUid, TokenInfo]) -> bool:
    """Check if this transaction should charge a fee.

    A transaction should charge a fee if it has at least one token with FEE version
    """
    if settings.FEE_FEATURE_FLAG is False:
        return False

    # Check if any token in the transaction has FEE version

    fee_tokens = [(uid, info) for uid, info in token_dict.items() if info.version is TokenInfoVersion.FEE]

    return len(fee_tokens) > 0


def collect_fee(settings: HathorSettings, fee: int, token_dict: dict[TokenUid, TokenInfo]) -> int:
    if fee == 0:
        return 0

    collected_fee = 0

    # Check fee payment
    for token_uid, token_info in token_dict.items():
        if token_info.amount == 0:
            # this token doesn't have a valid amount to pay, move to the next
            pass
        # the input wasn't spent, start charging the fee
        elif token_info.amount < 0 < fee:
            value_to_pay = 0
            token_amount = token_info.amount
            if token_uid == settings.HATHOR_TOKEN_UID:
                # the amount is a negative value, so we sum the paid fee in order to reduce the available value
                # limit the amount to the fee
                value_to_pay = min(abs(token_amount), fee)
                token_amount += value_to_pay
            elif token_info.version == TokenInfoVersion.DEPOSIT:
                token_htr_value = get_withdraw_amount(settings, token_amount)
                value_to_pay = min(token_htr_value, fee)
                token_amount += get_deposit_amount(settings, value_to_pay)

            token_dict[token_uid] = TokenInfo(token_amount, token_info.can_mint, token_info.can_melt,
                                              token_info.version)
            collected_fee += value_to_pay

    return collected_fee
