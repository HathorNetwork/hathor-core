# Copyright 2025 Hathor Labs
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

from hathor.indexes.rocksdb_vertex_timestamp_index import RocksDBVertexTimestampIndex
from hathor.indexes.scope import Scope
from hathor.transaction import BaseTransaction, Transaction

SCOPE = Scope(
    include_blocks=False,
    include_txs=True,
    include_voided=True,
)


class NCCreationIndex(RocksDBVertexTimestampIndex):
    """Index of Nano Contract creation txs sorted by their timestamps."""
    cf_name = b'nc-creation-index'
    db_name = 'nc-creation'

    def get_scope(self) -> Scope:
        return SCOPE

    def _should_add(self, tx: BaseTransaction) -> bool:
        if not tx.is_nano_contract():
            return False
        assert isinstance(tx, Transaction)
        nano_header = tx.get_nano_header()
        return nano_header.is_creating_a_new_contract()
