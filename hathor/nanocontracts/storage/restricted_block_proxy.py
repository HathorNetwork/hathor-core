# Copyright 2023 Hathor Labs
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

if TYPE_CHECKING:
    from hathor.nanocontracts.storage.block_storage import NCBlockStorage
    from hathor.nanocontracts.types import Address, Amount, TokenUid
    from hathor.transaction.token_info import TokenDescription, TokenVersion


class RestrictedBlockProxy:
    """A proxy used to limit access to only the tokens method of a block storage.
    """
    def __init__(self, block_storage: NCBlockStorage) -> None:
        self.__block_storage = block_storage

    def has_token(self, token_id: TokenUid) -> bool:
        """Proxy to block_storage.has_token()."""
        return self.__block_storage.has_token(token_id)

    def get_token(self, token_id: TokenUid) -> TokenDescription:
        """Proxy to block_storage.get_token()."""
        return self.__block_storage.get_token_description(token_id)

    def create_token(
        self,
        *,
        token_id: TokenUid,
        token_name: str,
        token_symbol: str,
        token_version: TokenVersion
    ) -> None:
        """Proxy to block_storage.create_token()."""
        self.__block_storage.create_token(
            token_id=token_id,
            token_name=token_name,
            token_symbol=token_symbol,
            token_version=token_version
        )

    def add_address_balance(self, address: Address, amount: Amount, token_id: TokenUid) -> None:
        """Proxy to block_storage.add_address_balance()."""
        self.__block_storage.add_address_balance(address, amount, token_id)
