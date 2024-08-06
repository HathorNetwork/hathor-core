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
from unittest.mock import Mock

from structlog import get_logger

from hathor.conf.get_settings import get_global_settings
from hathor.transaction import BaseTransaction
from hathor.transaction.static_metadata import BlockStaticMetadata, TransactionStaticMetadata, VertexStaticMetadata
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
        # We have to iterate over metadata instead of vertices because the storage doesn't allow us to get a vertex if
        # its static metadata is not set. We also use raw dict metadata because `metadata.create_from_json()` doesn't
        # include attributes that should be static, which are exactly the ones we need for this migration.
        metadata_iter = storage.iter_all_raw_metadata()

        for vertex_id, raw_metadata in progress(metadata_iter, log=log, total=None):
            height = raw_metadata['height']
            min_height = raw_metadata['min_height']
            bit_counts = raw_metadata.get('feature_activation_bit_counts')

            assert isinstance(height, int)
            assert isinstance(min_height, int)

            static_metadata: VertexStaticMetadata
            is_block = (vertex_id == settings.GENESIS_BLOCK_HASH or height != 0)

            if is_block:
                assert isinstance(bit_counts, list)
                for item in bit_counts:
                    assert isinstance(item, int)

                static_metadata = BlockStaticMetadata(
                    height=height,
                    min_height=min_height,
                    feature_activation_bit_counts=bit_counts,
                    feature_states={},  # This will be populated in the next PR
                )
            else:
                assert bit_counts is None or bit_counts == []
                static_metadata = TransactionStaticMetadata(
                    min_height=min_height
                )

            # We create a fake vertex with just the hash and static metadata, so we can use the existing
            # `storage._save_static_metadata()` instead of having to create an unsafe storage API that takes those
            # two arguments.
            vertex = Mock(spec_set=BaseTransaction)
            vertex.hash = vertex_id
            vertex.static_metadata = static_metadata
            storage._save_static_metadata(vertex)
