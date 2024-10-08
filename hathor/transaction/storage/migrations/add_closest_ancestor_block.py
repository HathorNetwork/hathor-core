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
from hathor.transaction import Transaction
from hathor.transaction.static_metadata import TransactionStaticMetadata
from hathor.transaction.storage.migrations import BaseMigration
from hathor.util import progress

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()


class Migration(BaseMigration):
    def skip_empty_db(self) -> bool:
        return True

    def get_db_name(self) -> str:
        return 'add_closest_ancestor_block'

    def run(self, storage: 'TransactionStorage') -> None:
        """This migration populates the closest_ancestor_block static metadata attribute of Transactions."""
        log = logger.new()
        settings = get_global_settings()
        topological_iter = storage.topological_iterator()

        for vertex in progress(topological_iter, log=log, total=None):
            if not isinstance(vertex, Transaction):
                # blocks don't have this attribute
                continue

            # We calculate the whole static metadata, which should be the same except for the closest_ancestor_block
            new_static_metadata = TransactionStaticMetadata.create_from_storage(vertex, settings, storage)
            assert vertex.static_metadata == new_static_metadata.copy(update=dict(closest_ancestor_block=b''))

            # We set the new static metadata manually and save it
            vertex._static_metadata = new_static_metadata
            storage.save_transaction(vertex, only_metadata=True)
