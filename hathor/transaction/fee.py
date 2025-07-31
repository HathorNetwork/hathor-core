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
from hathor.transaction import Transaction
from hathor.transaction.token_info import TokenInfoDict


# TODO: Remove this function and simply use the method directly
def calculate_fee(settings: HathorSettings, tx: Transaction, token_dict: TokenInfoDict) -> int:
    return token_dict.calculate_fee(settings)


def is_fee_tokens_enabled(settings: HathorSettings) -> bool:
    """Check if this transaction should charge a fee based on the FEE_FEATURE_FLAG
    """
    return settings.FEE_FEATURE_FLAG
