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
from typing import TYPE_CHECKING, Any

from twisted.internet.protocol import Factory
from twisted.protocols.tls import TLSMemoryBIOFactory

from hathor.indexes import RocksDBIndexesManager
from hathor.p2p import P2PDependencies
from hathor.p2p.dependencies.protocols import (
    P2PConnectionProtocol,
    P2PManagerProtocol,
    P2PVerificationServiceProtocol,
    P2PVertexHandlerProtocol,
)
from hathor.p2p.factory import HathorServerFactory
from hathor.p2p.netfilter.factory import NetfilterFactory
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_endpoint import PeerAddress
from hathor.storage import RocksDBStorage
from hathor.transaction.storage import TransactionCacheStorage, TransactionRocksDBStorage
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage
from hathor.transaction.vertex_parser import VertexParser
from hathor.utils.pydantic import BaseModel

if TYPE_CHECKING:
    from hathor.multiprocess.subprocess_runner import SubprocessBuildArgs, SubprocessBuildArtifacts

P2P_SUBPROCESS_CONNECTION_MAIN_FILE = Path(__file__)


class P2PSubprocessConnectionArgs(BaseModel):
    capabilities: list[str]
    whitelist_only: bool
    use_ssl: bool
    my_peer: dict[str, Any]
    cache_capacity: int | None
    cache_interval: int | None
    rocksdb_path: str
    rocksdb_cache_capacity: int | None


def build(args: SubprocessBuildArgs[P2PSubprocessConnectionArgs]) -> SubprocessBuildArtifacts:
    from hathor.multiprocess.ipc import IpcConnection
    from hathor.multiprocess.subprocess_runner import SubprocessBuildArtifacts
    vertex_parser = VertexParser(settings=args.settings)
    ipc_client = IpcConnection(reactor=args.reactor, socket_path='/tmp/test2.sock') \
        .set_custom_identity(str(args.addr))
    ipc_client.start()
    vertex_handler = ipc_client.get_proxy(P2PVertexHandlerProtocol)  # type: ignore[type-abstract]
    verification_service = ipc_client.get_proxy(P2PVerificationServiceProtocol)  # type: ignore[type-abstract]
    remote_p2p_manager = ipc_client.get_proxy(P2PManagerProtocol)  # type: ignore[type-abstract]
    my_peer = PrivatePeer.create_from_json(args.custom_args.my_peer)

    # TODO: use a remote ipc client instead of secondary
    rocksdb_storage = RocksDBStorage(
        path=args.custom_args.rocksdb_path,
        cache_capacity=args.custom_args.rocksdb_cache_capacity,
        secondary_path=f'{args.custom_args.rocksdb_path}/secondary_db/'
    )

    indexes = RocksDBIndexesManager(rocksdb_storage=rocksdb_storage)
    indexes.enable_mempool_index()

    tx_storage: BaseTransactionStorage = TransactionRocksDBStorage(
        settings=args.settings,
        vertex_parser=vertex_parser,
        rocksdb_storage=rocksdb_storage,
    )

    tx_storage = TransactionCacheStorage(
        reactor=args.reactor,
        settings=args.settings,
        store=tx_storage,
        indexes=indexes,
        capacity=args.custom_args.cache_capacity,
        interval=args.custom_args.cache_interval,
    )

    dependencies = P2PDependencies(
        reactor=args.reactor,
        settings=args.settings,
        vertex_parser=vertex_parser,
        vertex_handler=vertex_handler,
        verification_service=verification_service,
        tx_storage=tx_storage,
        capabilities=args.custom_args.capabilities,
        whitelist_only=args.custom_args.whitelist_only,
    )

    def exit_callback() -> None:
        ipc_client.stop()

    def built_protocol_callback(_addr: PeerAddress, protocol: P2PConnectionProtocol) -> None:
        ipc_client.register_service(protocol, as_protocol=P2PConnectionProtocol)  # type: ignore[type-abstract]

    factory: Factory = HathorServerFactory(
        my_peer=my_peer,
        p2p_manager=remote_p2p_manager,
        dependencies=dependencies,
        use_ssl=args.custom_args.use_ssl,
        built_protocol_callback=built_protocol_callback,
    )

    if args.custom_args.use_ssl:
        factory = TLSMemoryBIOFactory(my_peer.certificate_options, False, factory)

    return SubprocessBuildArtifacts(factory=factory, exit_callback=exit_callback)


if __name__ == '__main__':
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('localhost', port=8090, stdoutToServer=True, stderrToServer=True)
    from hathor.multiprocess.subprocess_runner import setup_subprocess_runner
    setup_subprocess_runner(build, P2PSubprocessConnectionArgs)
