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

import sys

from twisted.internet.defer import Deferred
from twisted.internet.endpoints import UNIXClientEndpoint, UNIXServerEndpoint, connectProtocol
from twisted.protocols import amp

from hathor.builder import SyncSupportLevel
from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.indexes import MemoryIndexesManager, RocksDBIndexesManager
from hathor.multiprocess.p2p_ipc_server import P2PIpcServerFactory
from hathor.p2p import P2PManager
from hathor.p2p.dependencies.multiprocess_p2p_dependencies import MultiprocessP2PDependencies
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_discovery import DNSPeerDiscovery
from hathor.reactor import ReactorProtocol, initialize_global_reactor
from hathor.storage import RocksDBStorage
from hathor.transaction.storage import TransactionMemoryStorage, TransactionRocksDBStorage, TransactionCacheStorage
from hathor.transaction.vertex_parser import VertexParser
from hathor.util import Random

P2P_IPC_MAIN = __file__


async def main(reactor: ReactorProtocol, settings: HathorSettings, inbound_socket: str, outbound_socket: str) -> None:
    client_endpoint = UNIXClientEndpoint(reactor=reactor, path=inbound_socket)
    client: amp.AMP = await connectProtocol(client_endpoint, amp.AMP())

    vertex_parser = VertexParser(settings=settings)
    rocksdb_storage = RocksDBStorage(open_as_secondary=True)
    indexes = RocksDBIndexesManager(rocksdb_storage)
    tx_rocksdb_storage = TransactionRocksDBStorage(
        rocksdb_storage=rocksdb_storage,
        settings=settings,
        vertex_parser=vertex_parser,
    )
    tx_storage = TransactionCacheStorage(
        reactor=reactor,
        settings=settings,
        store=tx_rocksdb_storage,
        indexes=indexes,
    )

    dependencies = MultiprocessP2PDependencies(
        reactor=reactor,
        settings=settings,
        client=client,
        vertex_parser=vertex_parser,
        tx_storage=tx_storage,
    )

    p2p_manager = P2PManager(
        dependencies=dependencies,
        my_peer=PrivatePeer.auto_generated(),
        ssl=True,
        rng=Random(),
        whitelist_only=False,
        capabilities=settings.get_default_capabilities(),
        sync_factories=SyncSupportLevel.get_factories(
            tx_storage=tx_storage,
            dependencies=dependencies,
            sync_v1_support=SyncSupportLevel.UNAVAILABLE,
            sync_v2_support=SyncSupportLevel.ENABLED,
        ),
        hostname=None,
    )
    p2p_manager.add_peer_discovery(DNSPeerDiscovery(settings.BOOTSTRAP_DNS))

    server_factory = P2PIpcServerFactory(p2p_manager=p2p_manager)
    server_endpoint = UNIXServerEndpoint(reactor=reactor, address=outbound_socket)
    server_endpoint.listen(server_factory)

if __name__ == '__main__':
    _, inbound_socket, outbound_socket = sys.argv
    reactor = initialize_global_reactor()
    settings = get_global_settings()
    Deferred.fromCoroutine(main(reactor, settings, inbound_socket, outbound_socket))
    reactor.run()
