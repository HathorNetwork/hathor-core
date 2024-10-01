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

from typing import Any

from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver
from typing_extensions import Self, override

from hathor.conf.settings import HathorSettings
from hathor.indexes.height_index import HeightInfo
from hathor.manager import HathorManager
from hathor.multiprocess import ipc
from hathor.multiprocess.ipc import IpcClient, IpcCommand, IpcServer
from hathor.p2p.peer import Peer
from hathor.p2p.peer_id import PeerId
from hathor.p2p.peer_storage import PeerStorage
from hathor.p2p.protocol import HathorProtocol
from hathor.p2p.sync_version import SyncVersion
from hathor.reactor import ReactorProtocol


class SyncMainIpcClient(IpcClient):
    __slots__ = ()


class SyncMainIpcServer(IpcServer):
    __slots__ = ('manager', '_line_receiver')

    def __init__(self, manager: HathorManager, line_receiver: SyncIpcLineReceiver) -> None:
        self.manager = manager
        self._line_receiver = line_receiver

    @override
    def get_cmd_map(self) -> dict[bytes, IpcCommand]:
        return {}


class SyncSubprocessIpcClient(IpcClient):
    __slots__ = ()



class SyncSubprocessIpcServer(IpcServer):
    __slots__ = ('_protocol',)

    @classmethod
    def build(
        cls,
        reactor: ReactorProtocol,
        settings: HathorSettings,
        client: SyncSubprocessIpcClient,
        kwargs: dict[str, Any],
    ) -> Self:
        my_peer = kwargs['my_peer']
        my_capabilities = kwargs['my_capabilities']
        use_ssl = kwargs['use_ssl']
        inbound = kwargs['inbound']
        assert isinstance(my_peer, Peer)
        assert isinstance(use_ssl, bool)
        assert isinstance(inbound, bool)

        protocol = HathorProtocol(
            reactor=reactor,
            settings=settings,
            my_peer=my_peer,
            client=client,
            my_capabilities=my_capabilities,
            use_ssl=use_ssl,
            inbound=inbound,
        )
        return cls(protocol)

    def __init__(self, protocol: HathorProtocol) -> None:
        self._protocol = protocol

    @override
    def get_cmd_map(self) -> dict[bytes, IpcCommand]:
        return {}


class SyncIpcLineReceiver(LineReceiver):
    __slots__ = ('_client',)

    def __init__(self, client: SyncMainIpcClient) -> None:
        self._client = client


class SyncIpcFactory(ServerFactory):
    __slots__ = ('reactor', 'manager', '_my_peer', '_use_ssl', '_inbound')

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        manager: HathorManager,
        my_peer: Peer,
        use_ssl: bool,
        inbound: bool,
    ) -> None:
        self.reactor = reactor
        self.manager = manager
        self._my_peer = my_peer,
        self._use_ssl = use_ssl,
        self._inbound = inbound

    @override
    def buildProtocol(self, addr: IAddress) -> SyncIpcLineReceiver:
        main_client = SyncMainIpcClient()
        line_receiver = SyncIpcLineReceiver(main_client)
        main_server = SyncMainIpcServer(self.manager, line_receiver)
        ipc.connect(
            main_reactor=self.reactor,
            main_client=main_client,
            main_server=main_server,
            subprocess_client_builder=SyncSubprocessIpcClient,
            subprocess_server_builder=SyncSubprocessIpcServer.build,
            subprocess_server_args=dict(
                my_peer=self._my_peer,
                my_capabilities=self.manager.capabilities,
                use_ssl=self._use_ssl,
                inbound=self._inbound,
            ),
            subprocess_name=str(getattr(addr, 'port'))  # TODO: What to use here
        )
        return line_receiver
