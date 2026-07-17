# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
