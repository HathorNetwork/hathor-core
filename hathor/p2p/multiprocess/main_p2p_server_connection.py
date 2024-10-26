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

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from hathor.indexes import RocksDBIndexesManager
from hathor.p2p import P2PDependencies
from hathor.p2p.factory import HathorServerFactory
from hathor.p2p.peer import PrivatePeer
from hathor.storage import RocksDBStorage
from hathor.transaction.storage import TransactionCacheStorage, TransactionRocksDBStorage
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage
from hathor.transaction.vertex_parser import VertexParser
from hathor.utils.pydantic import BaseModel

if TYPE_CHECKING:
    from hathor.multiprocess.main_subprocess_runner import SubprocessFactoryArgs

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


def build_p2p_server_factory(factory_args: SubprocessFactoryArgs) -> tuple[HathorServerFactory, Callable[[], None]]:
    from hathor.multiprocess.remote_ipc import IpcProxyType, RemoteIpcClient
    args = P2PServerConnectionArgs.parse_raw(factory_args.serialized_subprocess_args)
    vertex_parser = VertexParser(settings=factory_args.settings)
    vertex_handler = RemoteIpcClient(proxy_type=IpcProxyType.P2P_MANAGER, blocking=True)
    verification_service = RemoteIpcClient(proxy_type=IpcProxyType.P2P_MANAGER, blocking=True)
    remote_p2p_manager = RemoteIpcClient(proxy_type=IpcProxyType.P2P_MANAGER, blocking=True)
    my_peer = PrivatePeer.create_from_json(args.my_peer)

    rocksdb_storage = RocksDBStorage(
        path=args.rocksdb_path,
        cache_capacity=args.rocksdb_cache_capacity,
        secondary_path=f'{args.rocksdb_path}/secondary_db/'  # TODO: use a temp dir, then clean up
    )

    indexes = RocksDBIndexesManager(rocksdb_storage=rocksdb_storage)

    tx_storage: BaseTransactionStorage = TransactionRocksDBStorage(
        settings=factory_args.settings,
        vertex_parser=vertex_parser,
        rocksdb_storage=rocksdb_storage,
    )

    tx_storage = TransactionCacheStorage(
        reactor=factory_args.reactor,
        settings=factory_args.settings,
        store=tx_storage,
        indexes=indexes,
        capacity=args.cache_capacity,
        interval=args.cache_interval,
    )

    dependencies = P2PDependencies(
        reactor=factory_args.reactor,
        settings=factory_args.settings,
        vertex_parser=vertex_parser,
        vertex_handler=vertex_handler,
        verification_service=verification_service,
        tx_storage=tx_storage,
        capabilities=args.capabilities,
        whitelist_only=args.whitelist_only,
    )

    def exit_callback():
        remote_p2p_manager.stop()

    factory = HathorServerFactory(
        my_peer=my_peer,
        p2p_manager=remote_p2p_manager,
        dependencies=dependencies,
        use_ssl=args.use_ssl,
        build_protocol_callback=None,
    )

    return factory, exit_callback


if __name__ == '__main__':
    from hathor.multiprocess.main_subprocess_runner import main_subprocess_runner
    main_subprocess_runner(build_p2p_server_factory)
