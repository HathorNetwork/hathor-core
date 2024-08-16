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

from typing import TYPE_CHECKING

from structlog import get_logger

from hathor.conf.get_settings import get_global_settings
from hathor.transaction import Block, Transaction
from hathor.transaction.static_metadata import BlockStaticMetadata, TransactionStaticMetadata
from hathor.transaction.storage.migrations import BaseMigration
from hathor.util import progress

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()


class Migration(BaseMigration):
    def skip_empty_db(self) -> bool:
        return True

    def get_db_name(self) -> str:
        return 'migrate_static_metadata'

    def run(self, storage: 'TransactionStorage') -> None:
        """This migration takes attributes from existing vertex metadata and saves them as static metadata."""
        log = logger.new()
        settings = get_global_settings()

        # First we migrate static metadata using the storage itself since it uses internal structures.
        log.info('creating static metadata...')
        storage.migrate_static_metadata(log)

        # Now that static metadata is set, we can use the topological iterator normally
        log.info('removing old metadata and validating...')
        topological_iter = storage.topological_iterator()

        for vertex in progress(topological_iter, log=log, total=None):
            # We re-save the vertex's metadata so it's serialized with the new `to_bytes()` method, excluding fields
            # that were migrated.
            storage.save_transaction(vertex, only_metadata=True)

            # We re-create the static metadata from scratch and compare it with the value that was created by the
            # migration above, as a sanity check.
            if isinstance(vertex, Block):
                assert vertex.static_metadata == BlockStaticMetadata.create_from_storage(
                    vertex, settings, storage
                )
            elif isinstance(vertex, Transaction):
                assert vertex.static_metadata == TransactionStaticMetadata.create_from_storage(
                    vertex, settings, storage
                )
            else:
                raise NotImplementedError
