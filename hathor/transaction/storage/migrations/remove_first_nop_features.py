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
from hathor.transaction.storage.migrations import BaseMigration
from hathor.util import progress

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()


class Migration(BaseMigration):
    def skip_empty_db(self) -> bool:
        return True

    def get_db_name(self) -> str:
        return 'remove_first_nop_features'

    def run(self, storage: 'TransactionStorage') -> None:
        """
        This migration clears the Feature Activation metadata related to the first Phased Testing on testnet.
        """
        settings = get_global_settings()
        log = logger.new()

        if settings.NETWORK_NAME != 'testnet-golf':
            # If it's not testnet, we don't have to clear anything.
            log.info('Skipping testnet-only migration.')
            return

        topological_iterator = storage.topological_iterator()

        for vertex in progress(topological_iterator, log=log, total=None):
            if vertex.is_block:
                meta = vertex.get_metadata()
                assert meta.height is not None
                # This is the start_height of the **second** Phased Testing, so we clear anything before it.
                if meta.height < 3_386_880:
                    meta.feature_states = None

                    storage.save_transaction(vertex, only_metadata=True)
