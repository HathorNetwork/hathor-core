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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hathor.nanocontracts.storage import NCBlockStorage
    from hathor.nanocontracts.types import TokenUid as NCTokenUid
    from hathor.transaction.storage import TransactionStorage
    from hathor.transaction.token_info import TokenVersion
    from hathor.types import TokenUid as TokenUidType


def get_token_version(
    tx_storage: 'TransactionStorage',
    nc_block_storage: 'NCBlockStorage',
    token_uid: 'NCTokenUid | TokenUidType'
) -> 'TokenVersion':
    """
    Get the token version for a given token uid.
    It searches first in the tx storage and then in the block storage.
    """
    from hathor.transaction.exceptions import InvalidToken
    from hathor.transaction.storage.exceptions import TransactionDoesNotExist

    # First, try to get the token from a TokenCreationTransaction in tx storage
    try:
        token_creation_tx = tx_storage.get_token_creation_transaction(token_uid)
        return token_creation_tx.token_version
    except TransactionDoesNotExist:
        # If the token isn't found in the tx storage, try to fetch it from the block storage
        # This handles tokens created by nanocontracts
        from hathor.nanocontracts.types import TokenUid as NCTokenUid
        if nc_block_storage.has_token(NCTokenUid(token_uid)):
            # TODO-RAUL: add the token version after rebasing to create tokens syscall
            return TokenVersion(nc_block_storage.get_token_description(NCTokenUid(token_uid)).token_version)
        else:
            # Token wasn't found anywhere, this should not happen in normal validation
            raise InvalidToken(f'Token {NCTokenUid(token_uid).hex()} not found')
