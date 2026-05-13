#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import sys

from hathor.conf.get_settings import get_global_settings
from hathor.indexes import RocksDBIndexesManager
from hathor.reactor import initialize_global_reactor
from hathor.storage import RocksDBStorage
from hathor.transaction import Transaction
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor.transaction.vertex_parser import VertexParser
from hathorlib.nanocontracts.types import NCActionType

_, db_path, output_path = sys.argv

reactor = initialize_global_reactor()
settings = get_global_settings()
rocksdb_storage = RocksDBStorage(path=db_path)
vertex_parser = VertexParser(settings=settings)
indexes = RocksDBIndexesManager(rocksdb_storage, settings=settings)
storage = TransactionRocksDBStorage(
    reactor=reactor,
    settings=settings,
    rocksdb_storage=rocksdb_storage,
    vertex_parser=vertex_parser,
    indexes=indexes,
    nc_storage_factory=None,
    vertex_children_service=None,
    cache_config=None,
)

VALUE_SEPARATOR = ';'
COLUMNS = (
    'hash',
    'type',
    'size',
    'output_values',
    'nc_action_values',
)

with open(output_path, 'w') as f:
    f.write(','.join(COLUMNS))
    f.write('\n')

    count = 0
    for vertex in storage.get_all_transactions():
        count += 1
        if count % 10_000 == 0:
            print('processing', count)

        output_values = []
        for output in vertex.outputs:
            if not output.is_token_authority():
                output_values.append(str(output.value))

        nc_action_values = []
        if vertex.is_nano_contract():
            assert isinstance(vertex, Transaction)
            nano_header = vertex.get_nano_header()
            for action in nano_header.nc_actions:
                if action.type in (NCActionType.DEPOSIT, NCActionType.WITHDRAWAL):
                    nc_action_values.append(str(action.amount))

        values = (
            vertex.hash_hex,
            'b' if vertex.is_block else 't',
            str(len(bytes(vertex))),
            VALUE_SEPARATOR.join(output_values),
            VALUE_SEPARATOR.join(nc_action_values),
        )
        assert len(values) == len(COLUMNS)
        f.write(','.join(values))
        f.write('\n')
