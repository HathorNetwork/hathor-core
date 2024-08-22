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
        return 'migrate_feature_states'

    def run(self, storage: 'TransactionStorage') -> None:
        """This migration calculates feature states for blocks and saves them as static metadata."""
        log = logger.new()
        settings = get_global_settings()
        topological_iter = storage.topological_iterator()

        # The static metadata is set by the previous migration, so we can use the topological iterator normally
        for vertex in progress(topological_iter, log=log, total=None):
            if isinstance(vertex, Block):
                # We create the static metadata from scratch, which now includes feature states
                new_static_metadata = BlockStaticMetadata.create_from_storage(vertex, settings, storage)

                # We validate that it's the same as the current static metadata, except for feature states
                if vertex.is_genesis:
                    assert vertex.static_metadata == new_static_metadata
                else:
                    assert vertex.static_metadata.feature_states == {}
                    assert vertex.static_metadata == new_static_metadata.copy(update=dict(feature_states={}))

                # We set the new static metadata manually
                vertex._static_metadata = new_static_metadata
            elif isinstance(vertex, Transaction):
                # We re-create the static metadata from scratch and compare it with the value that was created by the
                # previous migration, as a sanity check.
                assert vertex.static_metadata == TransactionStaticMetadata.create_from_storage(
                    vertex, settings, storage
                )
            else:
                raise NotImplementedError

            # We re-save the vertex's metadata so it's serialized with the new `to_bytes()` method, excluding fields
            # that were migrated.
            storage.save_transaction(vertex, only_metadata=True)
