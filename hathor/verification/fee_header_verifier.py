#  Copyright 2023 Hathor Labs
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

from __future__ import annotations

from typing import Sequence

from hathor.transaction import Transaction
from hathor.transaction.exceptions import FeeHeaderTokenNotFound, InvalidFeeHeader
from hathor.transaction.headers import FeeHeader

MAX_FEES_LEN: int = 16


class FeeHeaderVerifier:

    @staticmethod
    def verify_fee_list(fee_header: 'FeeHeader', tx: Transaction) -> None:
        """Perform FeeHeader verifications that do not depend on the tx storage."""
        fees = fee_header.fees
        FeeHeaderVerifier._verify_fee_list_size('fees', len(fees))

        # Check for duplicate token indices in fees
        token_indices = [fee.token_index for fee in fees]
        FeeHeaderVerifier._verify_duplicate_indexes('fees', token_indices)

        from hathor.transaction.util import validate_fee_amount
        for fee in fees:
            FeeHeaderVerifier._verify_token_index('fees', fee.token_index, len(tx.tokens))
            validate_fee_amount(fee_header.settings, tx.get_token_uid(fee.token_index), fee.amount)

    @staticmethod
    def _verify_token_index(prop: str, token_index: int, tx_token_len: int) -> None:
        if token_index > tx_token_len:
            raise FeeHeaderTokenNotFound(
                f'{prop} contains token index {token_index} which is not in tokens list'
            )

    @staticmethod
    def _verify_duplicate_indexes(list_name: str, indexes: Sequence[int]) -> None:
        if len(indexes) != len(set(indexes)):
            raise InvalidFeeHeader(f'duplicate token indexes in {list_name} list')

    @staticmethod
    def _verify_fee_list_size(prop: str, list_len: int) -> None:
        if list_len == 0:
            raise InvalidFeeHeader(f'{prop} cannot be empty')

        if list_len > MAX_FEES_LEN:
            raise InvalidFeeHeader(f'more {prop} than the max allowed: {list_len} > {MAX_FEES_LEN}')
