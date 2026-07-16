# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hathorlib.nanocontracts.storage.block_storage import NCBlockStorage
    from hathorlib.nanocontracts.types import TokenUid
    from hathorlib.token_info import TokenDescription, TokenVersion


class TokenProxy:
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
