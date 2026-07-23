# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import final

from hathor.indexes.rocksdb_vertex_timestamp_index import RocksDBVertexTimestampIndex
from hathor.indexes.scope import Scope
from hathor.transaction import BaseTransaction

SCOPE = Scope(
    include_blocks=False,
    include_txs=True,
    include_voided=True,
)


class BlueprintTimestampIndex(RocksDBVertexTimestampIndex):
    """Index of on-chain Blueprints sorted by their timestamps."""
    cf_name = b'blueprint-index'
    db_name = 'on-chain-blueprints'

    def get_scope(self) -> Scope:
        return SCOPE

    @final
    def _should_add(self, tx: BaseTransaction) -> bool:
        from hathor.nanocontracts import OnChainBlueprint
        return isinstance(tx, OnChainBlueprint)
