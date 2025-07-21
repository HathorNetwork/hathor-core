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
from hathor.transaction import Transaction, TxOutput
from hathor.transaction.token_info import TokenInfo, TokenInfoVersion
from hathor.types import TokenUid


def calculate_fee(settings: HathorSettings, tx: Transaction, token_dict: dict[TokenUid, TokenInfo]) -> int:
    """Calculate the fee for this transaction.

    The fee is calculated based on fee tokens outputs. It sums up all tokens with TokenInfoVersion.FEE value.

    :return: The total fee in HTR
    :rtype: int
    """
    fee = 0
    spent_outputs_dict = get_non_authority_outputs(tx.get_spent_outputs_grouped_by_token_uid())
    outputs_dict = get_non_authority_outputs(tx.get_outputs_grouped_by_token_uid())

    for token_uid, token_info in token_dict.items():
        if token_uid is settings.HATHOR_TOKEN_UID or token_info.version is TokenInfoVersion.DEPOSIT:
            continue

        chargeable_outputs = outputs_dict.get(token_uid, [])
        chargeable_spent_outputs = spent_outputs_dict.get(token_uid, [])

        # melting fee-based token without producing outputs
        if len(chargeable_spent_outputs) > 0 and len(chargeable_outputs) == 0:
            fee += settings.FEE_PER_OUTPUT

        fee += len(chargeable_outputs) * settings.FEE_PER_OUTPUT
    return fee


def get_non_authority_outputs(outputs_dict: dict[TokenUid, list[TxOutput]]) -> dict[TokenUid, list[TxOutput]]:
    """
    Filters out token authority outputs from the given outputs dictionary.

    Args:
        outputs_dict (dict[TokenUid, list[TxOutput]]):
            A dictionary mapping token UIDs to their respective lists of transaction outputs.

    Returns:
        dict[TokenUid, list[TxOutput]]:
            A new dictionary with the same token UIDs, but only including outputs that are not token authorities.
    """
    filtered_dict: dict[TokenUid, list[TxOutput]] = {}
    for token_uid, outputs in outputs_dict.items():
        filtered_dict[token_uid] = [output for output in outputs if not output.is_token_authority()]
    return filtered_dict


def should_charge_fee(settings: HathorSettings) -> bool:
    """Check if this transaction should charge a fee based on the FEE_FEATURE_FLAG
    """
    return settings.FEE_FEATURE_FLAG
