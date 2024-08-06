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
        return 'migrate_feature_states'

    def run(self, storage: 'TransactionStorage') -> None:
        """This migration calculates feature states for blocks and saves them as static metadata."""
        from hathor.feature_activation.feature_service import FeatureService
        settings = get_global_settings()
        log = logger.new()
        topological_iterator = storage.topological_iterator()
        feature_service = FeatureService(
            settings=settings,
            vertex_getter=storage.get_vertex,
            block_by_height_getter=storage.get_block_by_height,
        )

        for vertex in progress(topological_iterator, log=log, total=None):
            if not isinstance(vertex, Block):
                continue
            feature_states = feature_service.calculate_all_feature_states(vertex, height=vertex.static_metadata.height)
            new_static_metadata = vertex.static_metadata.copy(update={'feature_states': feature_states})
            vertex._static_metadata = new_static_metadata
            storage._save_static_metadata(vertex)
