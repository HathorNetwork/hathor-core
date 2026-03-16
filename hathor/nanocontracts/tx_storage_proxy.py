#  Copyright 2026 Hathor Labs
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

from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionMetadataDoesNotExist
from hathorlib.nanocontracts.blueprint import Blueprint
from hathorlib.nanocontracts.types import BlueprintId, TokenUid
from hathorlib.token_info import TokenDescription


class TransactionStorageProxy:
    def __init__(self, storage: TransactionStorage):
        self.storage = storage

    def get_blueprint_class(self, blueprint_id: BlueprintId) -> type[Blueprint]:
        return self.storage.get_blueprint_class(blueprint_id)

    def get_token_description(self, token_uid: TokenUid) -> TokenDescription:
        # Check the transaction storage for existing tokens
        token_creation_tx = self.storage.get_token_creation_transaction(token_uid)

        if token_creation_tx.get_metadata().first_block is None:
            raise TransactionMetadataDoesNotExist(
                f"The {token_uid.hex()} token is not confirmed by any block"
            )

        return TokenDescription(
            token_version=token_creation_tx.token_version,
            token_name=token_creation_tx.token_name,
            token_symbol=token_creation_tx.token_symbol,
            token_id=token_creation_tx.hash
        )
