# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Set, Union

from structlog import get_logger
from twisted.internet import endpoints
from twisted.internet.base import ReactorBase
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IStreamClientEndpoint, IStreamServerEndpoint
from twisted.internet.task import LoopingCall
from twisted.protocols.tls import TLSMemoryBIOFactory, TLSMemoryBIOProtocol
from twisted.python.failure import Failure

from hathor.conf import HathorSettings
from hathor.p2p.downloader import Downloader
from hathor.p2p.netfilter.factory import NetfilterFactory
from hathor.p2p.peer_id import PeerId
from hathor.p2p.peer_storage import PeerStorage
from hathor.p2p.protocol import HathorProtocol
from hathor.p2p.states.ready import ReadyState
from hathor.p2p.utils import description_to_connection_string, parse_whitelist
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.transaction import BaseTransaction
from hathor.util import Random

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.p2p.factory import HathorClientFactory, HathorServerFactory
    from hathor.p2p.node_sync import NodeSyncTimestamp

logger = get_logger()
settings = HathorSettings()


class ConnectionsManager:
    """ It manages all peer-to-peer connections and events related to control messages.
    """

    connections: Set[HathorProtocol]
    connected_peers: Dict[str, HathorProtocol]
    connecting_peers: Dict[IStreamClientEndpoint, Deferred]
    handshaking_peers: Set[HathorProtocol]
    whitelist_only: bool

    def __init__(self, reactor: ReactorBase, my_peer: PeerId, server_factory: 'HathorServerFactory',
                 client_factory: 'HathorClientFactory', pubsub: PubSubManager, manager: 'HathorManager',
                 ssl: bool, rng: Random, whitelist_only: bool) -> None:
        self.log = logger.new()
        self.rng = rng

        self.reactor = reactor
        self.my_peer = my_peer

        # Factories.
        self.server_factory = server_factory
        self.server_factory.connections = self

        self.client_factory = client_factory
        self.client_factory.connections = self

        self.max_connections: int = settings.PEER_MAX_CONNECTIONS

        # All connections.
        self.connections = set()

        # List of pending connections.
        self.connecting_peers = {}  # Dict[IStreamClientEndpoint, twisted.internet.defer.Deferred]

        # List of peers connected but still not ready to communicate.
        self.handshaking_peers = set()  # Set[HathorProtocol]

        # List of peers connected and ready to communicate.
        self.connected_peers = {}  # Dict[string (peer.id), HathorProtocol]

        # List of peers received from the network.
        # We cannot trust their identity before we connect to them.
        self.received_peer_storage = PeerStorage()  # Dict[string (peer.id), PeerId]

        # List of known peers.
        self.peer_storage = PeerStorage()  # Dict[string (peer.id), PeerId]

        self.downloader = Downloader(manager)

        # A timer to try to reconnect to the disconnect known peers.
        self.lc_reconnect = LoopingCall(self.reconnect_to_all)
        self.lc_reconnect.clock = self.reactor

        # A timer to try to reconnect to the disconnect known peers.
        if settings.ENABLE_PEER_WHITELIST:
            self.wl_reconnect = LoopingCall(self.update_whitelist)
            self.wl_reconnect.clock = self.reactor

        # Pubsub object to publish events
        self.pubsub = pubsub

        self.ssl = ssl

        # Parameter to explicitly enable whitelist-only mode, when False it will still check the whitelist for sync-v1
        self.whitelist_only = whitelist_only

    def start(self) -> None:
        self.lc_reconnect.start(5, now=False)
        if settings.ENABLE_PEER_WHITELIST:
            self.wl_reconnect.start(30)

    def stop(self) -> None:
        if self.lc_reconnect.running:
            self.lc_reconnect.stop()

    def has_synced_peer(self) -> bool:
        """ Return whether we are synced to at least one peer.
        """
        connections = list(self.get_ready_connections())
        for conn in connections:
            assert conn.state is not None
            assert isinstance(conn.state, ReadyState)
            if conn.state.is_synced():
                return True
        return False

    def send_tx_to_peers(self, tx: BaseTransaction) -> None:
        """ Send `tx` to all ready peers.

        The connections are shuffled to fairly propagate among peers.
        It seems to be a good approach for a small number of peers. We need to analyze
        the best approach when the number of peers increase.

        :param tx: BaseTransaction to be sent.
        :type tx: py:class:`hathor.transaction.BaseTransaction`
        """
        connections = list(self.get_ready_connections())
        self.rng.shuffle(connections)
        for conn in connections:
            assert conn.state is not None
            assert isinstance(conn.state, ReadyState)
            conn.state.send_tx_to_peer(tx)

    def disconnect_all_peers(self, *, force: bool = False) -> None:
        """Disconnect all peers."""
        for conn in self.get_all_connections():
            conn.disconnect(force=force)

    def on_connection_failure(self, failure: Failure, peer: Optional[PeerId], endpoint: IStreamClientEndpoint) -> None:
        self.log.warn('connection failure', endpoint=endpoint, failure=failure.getErrorMessage())
        self.connecting_peers.pop(endpoint)
        if peer is not None:
            now = int(self.reactor.seconds())
            peer.increment_retry_attempt(now)

    def on_peer_connect(self, protocol: HathorProtocol) -> None:
        """Called when a new connection is established."""
        if len(self.connections) >= self.max_connections:
            self.log.warn('reached maximum number of connections', max_connections=self.max_connections)
            protocol.disconnect(force=True)
            return
        self.connections.add(protocol)
        self.handshaking_peers.add(protocol)

    def on_peer_ready(self, protocol: HathorProtocol) -> None:
        """Called when a peer is ready."""
        assert protocol.peer is not None
        assert protocol.peer.id is not None

        self.handshaking_peers.remove(protocol)
        self.received_peer_storage.pop(protocol.peer.id, None)

        self.peer_storage.add_or_merge(protocol.peer)

        # we emit the event even if it's a duplicate peer as a matching
        # NETWORK_PEER_DISCONNECTED will be emmited regardless
        self.pubsub.publish(HathorEvents.NETWORK_PEER_CONNECTED, protocol=protocol)

        if protocol.peer.id in self.connected_peers:
            # connected twice to same peer
            self.log.warn('duplicate connection to peer', protocol=protocol)
            conn = self.get_connection_to_drop(protocol)
            self.reactor.callLater(0, self.drop_connection, conn)
            if conn == protocol:
                # the new connection is being dropped, so don't save it to connected_peers
                return

        self.connected_peers[protocol.peer.id] = protocol

        # In case it was a retry, we must reset the data only here, after it gets ready
        protocol.peer.reset_retry_timestamp()

        # Notify other peers about this new peer connection.
        for conn in self.get_ready_connections():
            if conn != protocol:
                assert conn.state is not None
                assert isinstance(conn.state, ReadyState)
                conn.state.send_peers([protocol])

    def on_peer_disconnect(self, protocol: HathorProtocol) -> None:
        """Called when a peer disconnect."""
        self.connections.discard(protocol)
        if protocol in self.handshaking_peers:
            self.handshaking_peers.remove(protocol)
        if protocol.peer:
            assert protocol.peer.id is not None
            existing_protocol = self.connected_peers.pop(protocol.peer.id, None)
            if existing_protocol is None:
                # in this case, the connection was closed before it got to READY state
                return
            if existing_protocol != protocol:
                # this is the case we're closing a duplicate connection. We need to set the
                # existing protocol object back to connected_peers, as that connection is still ongoing.
                # A check for duplicate connections is done during PEER_ID state, but there's still a
                # chance it can happen if both connections start at the same time and none of them has
                # reached READY state while the other is on PEER_ID state
                self.connected_peers[protocol.peer.id] = existing_protocol
        self.pubsub.publish(HathorEvents.NETWORK_PEER_DISCONNECTED, protocol=protocol)

    def get_all_connections(self) -> Iterable[HathorProtocol]:
        """Iterate over all connections."""
        for conn in self.connections:
            yield conn

    def get_ready_connections(self) -> Set[HathorProtocol]:
        return set(self.connected_peers.values())

    def is_peer_connected(self, peer_id: str) -> bool:
        """
        :type peer_id: string (peer.id)
        """
        return peer_id in self.connected_peers

    def on_receive_peer(self, peer: PeerId, origin: Optional[ReadyState] = None) -> None:
        """ Update a peer information in our storage, and instantly attempt to connect
        to it if it is not connected yet.
        """
        if peer.id == self.my_peer.id:
            return
        self.received_peer_storage.add_or_merge(peer)
        self.connect_to_if_not_connected(peer, 0)

    def reconnect_to_all(self) -> None:
        """ It is called by the `lc_reconnect` timer and tries to connect to all known
        peers.

        TODO(epnichols): Should we always connect to *all*? Should there be a max #?
        """
        # when we have no connected peers left, run the discovery process again
        if len(self.connected_peers) < 1:
            # XXX: accessing manager through downloader because there is no other reference
            self.downloader.manager.do_discovery()
        now = int(self.reactor.seconds())
        for peer in self.peer_storage.values():
            self.connect_to_if_not_connected(peer, now)

    def update_whitelist(self) -> Deferred:
        from twisted.web.client import Agent, readBody
        from twisted.web.http_headers import Headers
        assert settings.WHITELIST_URL is not None
        self.log.info('update whitelist')
        agent = Agent(self.reactor)
        d = agent.request(
            b'GET',
            settings.WHITELIST_URL.encode(),
            Headers({'User-Agent': ['hathor-core']}),
            None)
        d.addCallback(readBody)
        d.addErrback(self._update_whitelist_err)
        d.addCallback(self._update_whitelist_cb)

    def _update_whitelist_err(self, *args: Any, **kwargs: Any) -> None:
        self.log.error('update whitelist failed', args=args, kwargs=kwargs)

    def _update_whitelist_cb(self, body: Optional[bytes]) -> None:
        if body is None:
            self.log.warn('update whitelist got no response')
            return
        else:
            self.log.info('update whitelist got response')
        try:
            text = body.decode()
            new_whitelist = parse_whitelist(text)
        except Exception:
            self.log.exception('failed to parse whitelist')
            return
        manager = self.downloader.manager  # XXX: maybe refactor later
        current_whitelist = set(manager.peers_whitelist)
        peers_to_add = new_whitelist - current_whitelist
        if peers_to_add:
            self.log.info('add new peers to whitelist', peers=peers_to_add)
        peers_to_remove = current_whitelist - new_whitelist
        if peers_to_remove:
            self.log.info('remove peers peers from whitelist', peers=peers_to_remove)
        for peer_id in peers_to_add:
            manager.add_peer_to_whitelist(peer_id)
        for peer_id in peers_to_remove:
            manager.remove_peer_from_whitelist_and_disconnect(peer_id)

    def connect_to_if_not_connected(self, peer: PeerId, now: int) -> None:
        """ Attempts to connect if it is not connected to the peer.
        """
        if not peer.entrypoints:
            return
        if peer.id in self.connected_peers:
            return

        assert peer.id is not None
        if peer.can_retry(now):
            self.connect_to(self.rng.choice(peer.entrypoints), peer)

    def _connect_to_callback(self, protocol: Union[HathorProtocol, TLSMemoryBIOProtocol], peer: Optional[PeerId],
                             endpoint: IStreamClientEndpoint, connection_string: str,
                             url_peer_id: Optional[str]) -> None:
        """Called when we successfully connect to a peer."""
        if isinstance(protocol, HathorProtocol):
            protocol.on_outbound_connect(url_peer_id, connection_string)
        else:
            protocol.wrappedProtocol.on_outbound_connect(url_peer_id, connection_string)
        self.connecting_peers.pop(endpoint)

    def connect_to(self, description: str, peer: Optional[PeerId] = None, use_ssl: Optional[bool] = None) -> None:
        """ Attempt to connect to a peer, even if a connection already exists.
        Usually you should call `connect_to_if_not_connected`.

        If `use_ssl` is True, then the connection will be wraped by a TLS.
        """
        if use_ssl is None:
            use_ssl = self.ssl
        connection_string, peer_id = description_to_connection_string(description)
        # When using twisted endpoints we can't have // in the connection string
        endpoint_url = connection_string.replace('//', '')
        endpoint = endpoints.clientFromString(self.reactor, endpoint_url)

        if use_ssl:
            certificate_options = self.my_peer.get_certificate_options()
            factory = TLSMemoryBIOFactory(certificate_options, True, self.client_factory)
        else:
            factory = self.client_factory

        deferred = endpoint.connect(factory)
        self.connecting_peers[endpoint] = deferred

        deferred.addCallback(self._connect_to_callback, peer, endpoint, connection_string, peer_id)
        deferred.addErrback(self.on_connection_failure, peer, endpoint)
        self.log.info('connect to ', endpoint=description)

    def listen(self, description: str, use_ssl: Optional[bool] = None) -> IStreamServerEndpoint:
        """ Start to listen to new connection according to the description.

        If `ssl` is True, then the connection will be wraped by a TLS.

        :Example:

        `manager.listen(description='tcp:8000')`

        :param description: A description of the protocol and its parameters.
        :type description: str
        """
        endpoint = endpoints.serverFromString(self.reactor, description)

        if use_ssl is None:
            use_ssl = self.ssl

        if use_ssl:
            certificate_options = self.my_peer.get_certificate_options()
            factory = TLSMemoryBIOFactory(certificate_options, False, self.server_factory)
        else:
            factory = self.server_factory

        factory = NetfilterFactory(self, factory)

        self.log.info('listen on', endpoint=description)
        endpoint.listen(factory)
        return endpoint

    def get_tx(self, hash_bytes: bytes, node_sync: 'NodeSyncTimestamp') -> Deferred:
        """ Request a tx from the downloader
        """
        return self.downloader.get_tx(hash_bytes, node_sync)

    def retry_get_tx(self, hash_bytes: bytes) -> None:
        """ Execute a retry of a request of a tx in the downloader
        """
        self.downloader.retry(hash_bytes)

    def get_connection_to_drop(self, protocol: HathorProtocol) -> HathorProtocol:
        """ When there are duplicate connections, determine which one should be dropped.

        We keep the connection initiated by the peer with larger id. A simple (peer_id1 > peer_id2)
        on the peer id string is used for this comparison.
        """
        assert protocol.peer is not None
        assert protocol.peer.id is not None
        assert protocol.my_peer.id is not None
        other_connection = self.connected_peers[protocol.peer.id]
        if protocol.my_peer.id > protocol.peer.id:
            # connection started by me is kept
            if not protocol.inbound:
                # other connection is dropped
                return other_connection
            else:
                # this was started by peer, so drop it
                return protocol
        else:
            # connection started by peer is kept
            if not protocol.inbound:
                return protocol
            else:
                return other_connection

    def drop_connection(self, protocol: HathorProtocol) -> None:
        """ Drop a connection
        """
        assert protocol.peer is not None
        self.log.debug('dropping connection', peer_id=protocol.peer.id, protocol=type(protocol).__name__)
        protocol.send_error_and_close_connection('Connection droped')

    def drop_connection_by_peer_id(self, peer_id: str) -> None:
        """ Drop a connection by peer id
        """
        protocol = self.connected_peers.get(peer_id)
        if protocol:
            self.drop_connection(protocol)
