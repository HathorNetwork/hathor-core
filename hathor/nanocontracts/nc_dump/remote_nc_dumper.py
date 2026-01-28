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

from __future__ import annotations

from enum import Enum
from io import TextIOBase
from typing import Any, AsyncIterator
from unittest.mock import Mock

from twisted.internet.defer import Deferred
from twisted.protocols.tls import TLSMemoryBIOFactory, TLSMemoryBIOProtocol
from typing_extensions import override

from hathor.conf.settings import HathorSettings
from hathor.nanocontracts.nc_dump.nc_dumper import DumpMode, NCDumper
from hathor.nanocontracts.storage.patricia_trie import DictChildren, Node, NodeId
from hathor.p2p.factory import HathorClientFactory
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.peer import PrivatePeer
from hathor.p2p.peer_endpoint import PeerAddress
from hathor.p2p.protocol import HathorProtocol
from hathor.p2p.states import HelloState, PeerIdState, ReadyState
from hathor.p2p.sync_factory import SyncAgentFactory
from hathor.p2p.sync_version import SyncVersion
from hathor.reactor import ReactorProtocol
from hathor.transaction import Block
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor.types import VertexId

_TIMEOUT = 10


class RemoteNCDumper(NCDumper):
    __slots__ = ('_reactor', '_address', '_peer', '_protocol', '_ready_deferred')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        reactor: ReactorProtocol,
        tx_storage: TransactionRocksDBStorage,
        start_block: VertexId | None,
        out: TextIOBase,
        mode: DumpMode,
        address: str,
        peer: PrivatePeer,
    ) -> None:
        super().__init__(settings=settings, tx_storage=tx_storage, start_block=start_block, out=out, mode=mode)

        self._reactor = reactor
        self._address = address
        self._peer = peer
        self._protocol: HathorProtocol | None = None
        self._ready_deferred: Deferred[None] = Deferred()

    @override
    async def dump(self) -> None:
        await self._connect()
        self._log.info('awaiting peer readiness')
        await self._ready_deferred
        self._log.info('peer ready')
        await super().dump()

    async def _connect(self) -> None:
        HathorProtocol.PeerState = FakePeerState  # type: ignore[misc, assignment]
        addr = PeerAddress.parse(self._address)
        self._log.info('connecting to peer', addr=addr)

        factory = HathorClientFactory(
            my_peer=self._peer,
            p2p_manager=FakeP2PManager(self._settings, self._reactor, self._ready_deferred),  # type: ignore[arg-type]
            settings=self._settings,
            use_ssl=True,
        )
        tls_factory = TLSMemoryBIOFactory(self._peer.certificate_options, isClient=True, wrappedFactory=factory)

        endpoint = addr.to_client_endpoint(self._reactor)
        protocol = await endpoint.connect(tls_factory)
        assert isinstance(protocol, TLSMemoryBIOProtocol)
        assert isinstance(protocol.wrappedProtocol, HathorProtocol)
        self._protocol = protocol.wrappedProtocol
        self._log.info('connected')

    @override
    async def _trie_iter_dfs(self, root_id: bytes) -> AsyncIterator[Node]:
        to_visit = [root_id]
        visited = set()

        while to_visit:
            node_id = to_visit.pop()
            visited.add(node_id)
            node = await self._get_node(node_id)
            yield node

            for child_id in node.children.values():
                if child_id not in visited:
                    to_visit.append(child_id)

    @override
    async def _get_block_root_id(self, block: Block) -> bytes:
        state = self._get_ready_state()
        state.send_get_block_nc_root_id(VertexId(block.hash))

        self._log.debug('awaiting block root', block=block.hash_hex)
        assert state.nc_block_root_id_deferred is not None
        vertex_id, node_id = await state.nc_block_root_id_deferred
        assert vertex_id == block.hash
        return node_id

    async def _get_node(self, node_id: bytes) -> Node:
        state = self._get_ready_state()
        state.send_get_nc_db_node(NodeId(node_id))

        self._log.debug('awaiting node', node_id=node_id.hex())
        assert state.nc_node_deferred is not None
        data = await state.nc_node_deferred
        id_ = data['id']
        key = data['key']
        content = data.get('content')
        children_data = data.get('children', {})
        children = {bytes.fromhex(k): NodeId(bytes.fromhex(v)) for k, v in children_data.items()}

        return Node(
            _id=NodeId(bytes.fromhex(id_)),
            key=bytes.fromhex(key),
            length=0,
            content=bytes.fromhex(content) if content else None,
            children=DictChildren(children),
        )

    def _get_ready_state(self) -> FakeReadyState:
        assert self._protocol is not None
        state = self._protocol.state
        assert isinstance(state, FakeReadyState)
        return state


class FakeHathorManager:
    __slots__ = ('reactor', 'capabilities', 'peers_whitelist')

    def __init__(self, settings: HathorSettings, reactor: ReactorProtocol) -> None:
        self.reactor = reactor
        self.capabilities = [
            settings.CAPABILITY_WHITELIST,
            settings.CAPABILITY_SYNC_VERSION,
            settings.CAPABILITY_GET_BEST_BLOCKCHAIN,
            settings.CAPABILITY_IPV6,
            settings.CAPABILITY_NANO_STATE
        ]

        self.peers_whitelist = FakePeerWhitelist()

    def has_sync_version_capability(self) -> bool:
        return True


class FakeP2PManager:
    __slots__ = ('settings', 'reactor', 'manager', 'rng', '_ready_deferred')

    def __init__(self, settings: HathorSettings, reactor: ReactorProtocol, ready_deferred: Deferred[None]) -> None:
        self.settings = settings
        self.reactor = reactor
        self.manager = FakeHathorManager(settings, reactor)
        self.rng = object()
        self._ready_deferred = ready_deferred

    def get_enabled_sync_versions(self) -> set[SyncVersion]:
        return {SyncVersion.V2}

    def on_peer_disconnect(self, _: Any) -> None:
        pass

    def on_peer_connect(self, _: Any) -> None:
        pass

    def is_peer_connected(self, _: Any) -> bool:
        return False

    def get_sync_factory(self, _: Any) -> SyncAgentFactory:
        agent = Mock()
        agent.get_cmd_dict = Mock(return_value={})
        factory = Mock()
        factory.create_sync_agent = Mock(return_value=agent)
        return factory


class FakePeerWhitelist:
    __slots__ = ()

    def __contains__(self, item: Any) -> bool:
        return True


class FakeReadyState(ReadyState):
    __slots__ = ('nc_block_root_id_deferred', 'nc_node_deferred')

    def __init__(self, protocol: HathorProtocol, settings: HathorSettings) -> None:
        super().__init__(protocol, settings)

        self.cmd_map.update({
            ProtocolMessages.PONG: lambda _: None,
            ProtocolMessages.GET_PEERS: lambda _: None,
            ProtocolMessages.PEERS: lambda _: None,
            ProtocolMessages.GET_BEST_BLOCKCHAIN: lambda _: None,
            ProtocolMessages.BEST_BLOCKCHAIN: lambda _: None,
            ProtocolMessages.GET_BLOCK_NC_ROOT_ID: lambda _: None,
            ProtocolMessages.GET_NC_DB_NODE: lambda _: None,
            ProtocolMessages.GET_NEXT_BLOCKS: lambda _: None,
            ProtocolMessages.BLOCKS: lambda _: None,
            ProtocolMessages.BLOCKS_END: lambda _: None,
            ProtocolMessages.GET_BEST_BLOCK: lambda _: None,
            ProtocolMessages.BEST_BLOCK: lambda _: None,
            ProtocolMessages.GET_TRANSACTIONS_BFS: lambda _: None,
            ProtocolMessages.TRANSACTION: lambda _: None,
            ProtocolMessages.TRANSACTIONS_END: lambda _: None,
            ProtocolMessages.GET_PEER_BLOCK_HASHES: lambda _: None,
            ProtocolMessages.PEER_BLOCK_HASHES: lambda _: None,
            ProtocolMessages.STOP_BLOCK_STREAMING: lambda _: None,
            ProtocolMessages.STOP_TRANSACTIONS_STREAMING: lambda _: None,
            ProtocolMessages.GET_TIPS: lambda _: None,
            ProtocolMessages.TIPS: lambda _: None,
            ProtocolMessages.TIPS_END: lambda _: None,
            ProtocolMessages.GET_DATA: lambda _: None,
            ProtocolMessages.DATA: lambda _: None,
            ProtocolMessages.RELAY: lambda _: None,
            ProtocolMessages.NOT_FOUND: lambda _: None,
        })

        self.nc_block_root_id_deferred: Deferred[tuple[bytes, NodeId]] | None = None
        self.nc_node_deferred: Deferred[dict[str, Any]] | None = None

    def on_enter(self) -> None:
        p2p = self.protocol.connections
        assert isinstance(p2p, FakeP2PManager)
        p2p._ready_deferred.callback(None)

    def on_exit(self) -> None:
        pass

    def prepare_to_disconnect(self) -> None:
        pass

    def send_get_block_nc_root_id(self, block_hash: bytes) -> None:
        assert self.nc_block_root_id_deferred is None
        self.nc_block_root_id_deferred = Deferred()
        super().send_get_block_nc_root_id(block_hash)

    def send_get_nc_db_node(self, node_id: NodeId) -> None:
        assert self.nc_node_deferred is None
        self.nc_node_deferred = Deferred()
        super().send_get_nc_db_node(node_id)

    def handle_block_nc_root_id(self, payload: str) -> None:
        super().handle_block_nc_root_id(payload)
        assert self.peer_nc_block_root_id is not None
        assert self.nc_block_root_id_deferred is not None
        d, self.nc_block_root_id_deferred = self.nc_block_root_id_deferred, None
        d.callback(self.peer_nc_block_root_id)

    def handle_nc_db_node(self, payload: str) -> None:
        super().handle_nc_db_node(payload)
        assert self.peer_nc_node is not None
        assert self.nc_node_deferred is not None
        d, self.nc_node_deferred = self.nc_node_deferred, None
        d.callback(self.peer_nc_node)


class FakePeerState(Enum):
    HELLO = HelloState
    PEER_ID = PeerIdState
    READY = FakeReadyState
