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

import os
import sys
import tempfile
import time

from twisted.internet import protocol
from twisted.internet.endpoints import UNIXClientEndpoint, UNIXServerEndpoint, connectProtocol
from twisted.internet.interfaces import IProcessTransport
from twisted.protocols import amp

from hathor.multiprocess.node_ipc_server import NodeIpcServerFactory
from hathor.multiprocess.p2p_ipc_main import P2P_IPC_MAIN
from hathor.multiprocess.p2p_ipc_server import Start
from hathor.p2p.factory import HathorClientFactory, HathorServerFactory
from hathor.p2p.peer_discovery import PeerDiscovery
from hathor.p2p.protocol import HathorProtocol
from hathor.p2p.sync_version import SyncVersion
from hathor.reactor import ReactorProtocol
from hathor.transaction import BaseTransaction
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.vertex_parser import VertexParser
from hathor.vertex_handler import VertexHandler


class MultiprocessP2PManager:
    __slots__ = ('reactor', 'vertex_parser', 'vertex_handler', 'tx_storage', '_tmp_dir', '_subprocess')

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        vertex_parser: VertexParser,
        vertex_handler: VertexHandler,
        tx_storage: TransactionStorage,
    ) -> None:
        self.reactor = reactor
        self.vertex_parser = vertex_parser
        self.vertex_handler = vertex_handler
        self.tx_storage = tx_storage
        self._tmp_dir: tempfile.TemporaryDirectory | None = None
        self._subprocess: IProcessTransport | None = None

    async def start(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        outbound_socket = os.path.join(self._tmp_dir.name, 'out.sock')
        inbound_socket = os.path.join(self._tmp_dir.name, 'in.sock')

        server_factory = NodeIpcServerFactory(vertex_parser=self.vertex_parser, vertex_handler=self.vertex_handler, tx_storage=self.tx_storage)
        server_endpoint = UNIXServerEndpoint(reactor=self.reactor, address=outbound_socket)
        server_endpoint.listen(server_factory)

        self._subprocess = self.reactor.spawnProcess(
            processProtocol=protocol.ProcessProtocol(),
            executable=sys.executable,
            args=[sys.executable, P2P_IPC_MAIN, outbound_socket, inbound_socket],
            env=os.environ,
            childFDs={1: 1, 2: 2},
        )

        client_endpoint = UNIXClientEndpoint(reactor=self.reactor, path=inbound_socket)
        time.sleep(2)  # TODO: Couldn't use timeout in endpoint? Improve this
        client: amp.AMP = await connectProtocol(client_endpoint, amp.AMP())
        await client.callRemote(Start)

    def stop(self) -> None:
        assert self._tmp_dir is not None
        assert self._subprocess is not None
        self._subprocess.signalProcess('INT')
        self._tmp_dir.cleanup()

    def get_connections(self) -> set[HathorProtocol]:
        return set()

    def get_server_factory(self) -> HathorServerFactory:
        raise NotImplementedError

    def get_client_factory(self) -> HathorClientFactory:
        raise NotImplementedError

    def enable_localhost_only(self) -> None:
        raise NotImplementedError

    def has_synced_peer(self) -> bool:
        return False

    def send_tx_to_peers(self, tx: BaseTransaction) -> None:
        raise NotImplementedError

    def reload_entrypoints_and_connections(self) -> None:
        raise NotImplementedError

    def enable_sync_version(self, sync_version: SyncVersion) -> None:
        raise NotImplementedError

    def add_peer_discovery(self, peer_discovery: PeerDiscovery) -> None:
        return
        raise NotImplementedError

    def add_listen_address_description(self, addr: str) -> None:
        raise NotImplementedError

    def disconnect_all_peers(self, *, force: bool = False) -> None:
        raise NotImplementedError
