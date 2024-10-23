#  Copyright 2024 Hathor Labs
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

from pathlib import Path
from typing import Any

from hathor.conf.settings import HathorSettings
from hathor.indexes import RocksDBIndexesManager
from hathor.multiprocess.main_subprocess_runner import main_subprocess_runner
from hathor.p2p import P2PDependencies
from hathor.p2p.factory import HathorServerFactory
from hathor.p2p.multiprocess.remote_p2p_manager import RemoteP2PManager
from hathor.p2p.multiprocess.remote_verification_service import RemoteVerificationService
from hathor.p2p.multiprocess.remote_vertex_handler import RemoteVertexHandler
from hathor.p2p.peer import PrivatePeer
from hathor.reactor import ReactorProtocol
from hathor.storage import RocksDBStorage
from hathor.transaction.storage import TransactionCacheStorage, TransactionRocksDBStorage
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage
from hathor.transaction.vertex_parser import VertexParser
from hathor.utils.pydantic import BaseModel

MAIN_P2P_SERVER_CONNECTION_FILE = Path(__file__)


class P2PServerConnectionArgs(BaseModel):
    capabilities: list[str]
    whitelist_only: bool
    use_ssl: bool
    my_peer: dict[str, Any]
    cache_capacity: int | None
    cache_interval: int | None
    rocksdb_path: str
    rocksdb_cache_capacity: int | None


def build_p2p_server_factory(
    reactor: ReactorProtocol,
    settings: HathorSettings,
    serialized_args: bytes
) -> HathorServerFactory:
    args = P2PServerConnectionArgs.parse_raw(serialized_args)
    vertex_parser = VertexParser(settings=settings)
    vertex_handler = RemoteVertexHandler()
    verification_service = RemoteVerificationService()
    p2p_manager = RemoteP2PManager()
    my_peer = PrivatePeer.create_from_json(args.my_peer)

    rocksdb_storage = RocksDBStorage(
        path=args.rocksdb_path,
        cache_capacity=args.rocksdb_cache_capacity,
        secondary_path=f'{args.rocksdb_path}/secondary_db/'  # TODO: use a temp dir, then clean up
    )

    indexes = RocksDBIndexesManager(rocksdb_storage=rocksdb_storage)

    tx_storage: BaseTransactionStorage = TransactionRocksDBStorage(
        settings=settings,
        vertex_parser=vertex_parser,
        rocksdb_storage=rocksdb_storage,
    )

    tx_storage = TransactionCacheStorage(
        reactor=reactor,
        settings=settings,
        store=tx_storage,
        indexes=indexes,
        capacity=args.cache_capacity,
        interval=args.cache_interval,
    )

    dependencies = P2PDependencies(
        reactor=reactor,
        settings=settings,
        vertex_parser=vertex_parser,
        vertex_handler=vertex_handler,
        verification_service=verification_service,
        tx_storage=tx_storage,
        capabilities=args.capabilities,
        whitelist_only=args.whitelist_only,
    )

    return HathorServerFactory(
        my_peer=my_peer,
        p2p_manager=p2p_manager,
        dependencies=dependencies,
        use_ssl=args.use_ssl,
    )


if __name__ == '__main__':
    main_subprocess_runner(build_p2p_server_factory)
