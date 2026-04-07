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

from hathor.feature_activation.storage.feature_activation_storage import FeatureActivationStorage
from hathor.transaction import Block
from hathor.transaction.storage.migrations import BaseMigration
from hathor.util import progress

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()


class Migration(BaseMigration):
    def skip_empty_db(self) -> bool:
        return True

    def get_db_name(self) -> str:
        return 'reset_feature_state_cache'

    def run(self, storage: 'TransactionStorage') -> None:
        from hathor.transaction.storage import TransactionRocksDBStorage
        log = logger.new()
        assert isinstance(storage, TransactionRocksDBStorage)
        feature_activation_storage = FeatureActivationStorage(
            settings=storage._settings,
            rocksdb_storage=storage._rocksdb_storage,
        )

        log.info('resetting existing feature activation settings...')
        feature_activation_storage.reset_settings()

        log.info('cleaning up feature states cache...')
        for vertex in progress(storage.get_all_transactions(), log=log, total=None):
            meta = vertex.get_metadata()
            if isinstance(vertex, Block):
                meta.feature_states = None
                storage.save_transaction(vertex, only_metadata=True)
            else:
                assert meta.feature_states is None
