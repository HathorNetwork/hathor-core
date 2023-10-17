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

from typing import TYPE_CHECKING, Any, Iterable, NamedTuple, Optional, Union

from structlog import get_logger
from twisted.internet import endpoints
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IProtocolFactory, IStreamClientEndpoint, IStreamServerEndpoint
from twisted.internet.task import LoopingCall
from twisted.protocols.tls import TLSMemoryBIOFactory, TLSMemoryBIOProtocol
from twisted.python.failure import Failure

from hathor.conf import HathorSettings
from hathor.p2p.netfilter.factory import NetfilterFactory
from hathor.p2p.peer_discovery import PeerDiscovery
from hathor.p2p.peer_id import PeerId
from hathor.p2p.peer_storage import PeerStorage
from hathor.p2p.protocol import HathorProtocol
from hathor.p2p.rate_limiter import RateLimiter
from hathor.p2p.states.ready import ReadyState
from hathor.p2p.sync_factory import SyncAgentFactory
from hathor.p2p.sync_version import SyncVersion
from hathor.p2p.utils import description_to_connection_string, parse_whitelist
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.transaction import BaseTransaction
from hathor.util import Random, Reactor

if TYPE_CHECKING:
    from twisted.internet.interfaces import IDelayedCall

    from hathor.manager import HathorManager

logger = get_logger()
settings = HathorSettings()

# The timeout in seconds for the whitelist GET request
WHITELIST_REQUEST_TIMEOUT = 45


class _SyncRotateInfo(NamedTuple):
    candidates: list[str]
    old: set[str]
    new: set[str]
    to_disable: set[str]
    to_enable: set[str]


class _ConnectingPeer(NamedTuple):
    connection_string: str
    endpoint_deferred: Deferred


class PeerConnectionsMetrics(NamedTuple):
    connecting_peers_count: int
    handshaking_peers_count: int
    connected_peers_count: int
    known_peers_count: int


class ConnectionsManager:
    """ It manages all peer-to-peer connections and events related to control messages.
    """
    MAX_ENABLED_SYNC = settings.MAX_ENABLED_SYNC
    SYNC_UPDATE_INTERVAL = settings.SYNC_UPDATE_INTERVAL
    PEER_DISCOVERY_INTERVAL = settings.PEER_DISCOVERY_INTERVAL

    class GlobalRateLimiter:
        SEND_TIPS = 'NodeSyncTimestamp.send_tips'

    manager: Optional['HathorManager']
    connections: set[HathorProtocol]
    connected_peers: dict[str, HathorProtocol]
    connecting_peers: dict[IStreamClientEndpoint, _ConnectingPeer]
    handshaking_peers: set[HathorProtocol]
    whitelist_only: bool
    _sync_factories: dict[SyncVersion, SyncAgentFactory]

    rate_limiter: RateLimiter

    def __init__(self,
                 reactor: Reactor,
                 network: str,
                 my_peer: PeerId,
                 pubsub: PubSubManager,
                 ssl: bool,
                 rng: Random,
                 whitelist_only: bool,
                 enable_sync_v1: bool,
                 enable_sync_v2: bool,
                 enable_sync_v1_1: bool) -> None:
        from hathor.p2p.sync_v1.factory_v1_0 import SyncV10Factory
        from hathor.p2p.sync_v1.factory_v1_1 import SyncV11Factory
        from hathor.p2p.sync_v2.factory import SyncV2Factory

        if not (enable_sync_v1 or enable_sync_v1_1 or enable_sync_v2):
            raise TypeError(f'{type(self).__name__}() at least one sync version is required')

        self.log = logger.new()
        self.rng = rng
        self.manager = None

        self.reactor = reactor
        self.my_peer = my_peer

        self.network = network

        # List of addresses to listen for new connections (eg: [tcp:8000])
        self.listen_addresses: list[str] = []

        # List of peer discovery methods.
        self.peer_discoveries: list[PeerDiscovery] = []

        # Options
        self.localhost_only = False

        # Factories.
        from hathor.p2p.factory import HathorClientFactory, HathorServerFactory
        self.use_ssl = ssl
        self.server_factory = HathorServerFactory(self.network, self.my_peer, p2p_manager=self, use_ssl=self.use_ssl)
        self.client_factory = HathorClientFactory(self.network, self.my_peer, p2p_manager=self, use_ssl=self.use_ssl)

        # Global maximum number of connections.
        self.max_connections: int = settings.PEER_MAX_CONNECTIONS

        # Global rate limiter for all connections.
        self.rate_limiter = RateLimiter(self.reactor)
        self.enable_rate_limiter()

        # All connections.
        self.connections = set()

        # List of pending connections.
        self.connecting_peers = {}

        # List of peers connected but still not ready to communicate.
        self.handshaking_peers = set()

        # List of peers connected and ready to communicate.
        self.connected_peers = {}

        # List of peers received from the network.
        # We cannot trust their identity before we connect to them.
        self.received_peer_storage = PeerStorage()

        # List of known peers.
        self.peer_storage = PeerStorage()  # dict[string (peer.id), PeerId]

        # A timer to try to reconnect to the disconnect known peers.
        self.lc_reconnect = LoopingCall(self.reconnect_to_all)
        self.lc_reconnect.clock = self.reactor

        # A timer to update sync of all peers.
        self.lc_sync_update = LoopingCall(self.sync_update)
        self.lc_sync_update.clock = self.reactor
        self.lc_sync_update_interval: float = 5  # seconds

        # Peers that always have sync enabled.
        self.always_enable_sync: set[str] = set()

        # Timestamp of the last time sync was updated.
        self._last_sync_rotate: float = 0.

        # A timer to try to reconnect to the disconnect known peers.
        if settings.ENABLE_PEER_WHITELIST:
            self.wl_reconnect = LoopingCall(self.update_whitelist)
            self.wl_reconnect.clock = self.reactor

        # Pubsub object to publish events
        self.pubsub = pubsub

        # Parameter to explicitly enable whitelist-only mode, when False it will still check the whitelist for sync-v1
        self.whitelist_only = whitelist_only

        self.enable_sync_v1 = enable_sync_v1
        self.enable_sync_v1_1 = enable_sync_v1_1
        self.enable_sync_v2 = enable_sync_v2

        # Timestamp when the last discovery ran
        self._last_discovery: float = 0.

        # sync-manager factories
        self._sync_factories = {}
        if enable_sync_v1:
            self._sync_factories[SyncVersion.V1] = SyncV10Factory(self)
        if enable_sync_v1_1:
            self._sync_factories[SyncVersion.V1_1] = SyncV11Factory(self)
        if enable_sync_v2:
            self._sync_factories[SyncVersion.V2] = SyncV2Factory(self)

    def set_manager(self, manager: 'HathorManager') -> None:
        """Set the manager. This method must be called before start()."""
        self.manager = manager
        if self.enable_sync_v2:
            assert self.manager.tx_storage.indexes is not None
            indexes = self.manager.tx_storage.indexes
            self.log.debug('enable sync-v2 indexes')
            indexes.enable_deps_index()
            indexes.enable_mempool_index()

    def add_listen_address(self, addr: str) -> None:
        """Add address to listen for incoming connections."""
        self.listen_addresses.append(addr)

    def add_peer_discovery(self, peer_discovery: PeerDiscovery) -> None:
        """Add a peer discovery method."""
        self.peer_discoveries.append(peer_discovery)

    def do_discovery(self) -> None:
        """
        Do a discovery and connect on all discovery strategies.
        """
        for peer_discovery in self.peer_discoveries:
            peer_discovery.discover_and_connect(self.connect_to)

    def disable_rate_limiter(self) -> None:
        """Disable global rate limiter."""
        self.rate_limiter.unset_limit(self.GlobalRateLimiter.SEND_TIPS)
        self.rate_limiter.reset(self.GlobalRateLimiter.SEND_TIPS)

    def enable_rate_limiter(self, max_hits: int = 16, window_seconds: float = 1) -> None:
        """Enable global rate limiter. This method can be called to change the current rate limit."""
        self.rate_limiter.set_limit(
            self.GlobalRateLimiter.SEND_TIPS,
            max_hits,
            window_seconds
        )

    def start(self) -> None:
        self.lc_reconnect.start(5, now=False)
        self.lc_sync_update.start(self.lc_sync_update_interval, now=False)

        if settings.ENABLE_PEER_WHITELIST:
            self._start_whitelist_reconnect()

        for description in self.listen_addresses:
            self.listen(description)

        self.do_discovery()

    def _start_whitelist_reconnect(self) -> None:
        # The deferred returned by the LoopingCall start method
        # executes when the looping call stops running
        # https://docs.twistedmatrix.com/en/stable/api/twisted.internet.task.LoopingCall.html
        d = self.wl_reconnect.start(30)
        d.addErrback(self._handle_whitelist_reconnect_err)

    def _handle_whitelist_reconnect_err(self, *args: Any, **kwargs: Any) -> None:
        """ This method will be called when an exception happens inside the whitelist update
            and ends up stopping the looping call.
            We log the error and start the looping call again.
        """
        self.log.error('whitelist reconnect had an exception. Start looping call again.', args=args, kwargs=kwargs)
        self.reactor.callLater(30, self._start_whitelist_reconnect)

    def stop(self) -> None:
        if self.lc_reconnect.running:
            self.lc_reconnect.stop()

        if self.lc_sync_update.running:
            self.lc_sync_update.stop()

    def _get_peers_count(self) -> PeerConnectionsMetrics:
        """Get a dict containing the count of peers in each state"""

        return PeerConnectionsMetrics(
            len(self.connecting_peers),
            len(self.handshaking_peers),
            len(self.connected_peers),
            len(self.peer_storage)
        )

    def get_sync_versions(self) -> set[SyncVersion]:
        """Set of versions that were enabled and are supported."""
        assert self.manager is not None
        if self.manager.has_sync_version_capability():
            return set(self._sync_factories.keys())
        else:
            assert SyncVersion.V1 in self._sync_factories, 'sync-versions capability disabled, but sync-v1 not enabled'
            # XXX: this is to make it easy to simulate old behavior if we disable the sync-version capability
            return {SyncVersion.V1}

    def get_sync_factory(self, sync_version: SyncVersion) -> SyncAgentFactory:
        """Get the sync factory for a given version, support MUST be checked beforehand or it will raise an assert."""
        assert sync_version in self._sync_factories, 'get_sync_factory must be called for a supported version'
        return self._sync_factories[sync_version]

    def has_synced_peer(self) -> bool:
        """ Return whether we are synced to at least one peer.
        """
        connections = list(self.iter_ready_connections())
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
        connections = list(self.iter_ready_connections())
        self.rng.shuffle(connections)
        for conn in connections:
            assert conn.state is not None
            assert isinstance(conn.state, ReadyState)
            conn.state.send_tx_to_peer(tx)

    def disconnect_all_peers(self, *, force: bool = False) -> None:
        """Disconnect all peers."""
        for conn in self.iter_all_connections():
            conn.disconnect(force=force)

    def on_connection_failure(self, failure: Failure, peer: Optional[PeerId], endpoint: IStreamClientEndpoint) -> None:
        connecting_peer = self.connecting_peers[endpoint]
        connection_string = connecting_peer.connection_string
        self.log.warn('connection failure', endpoint=connection_string, failure=failure.getErrorMessage())
        self.connecting_peers.pop(endpoint)

        self.pubsub.publish(
            HathorEvents.NETWORK_PEER_CONNECTION_FAILED,
            peer=peer,
            peers_count=self._get_peers_count()
        )

    def on_peer_connect(self, protocol: HathorProtocol) -> None:
        """Called when a new connection is established."""
        if len(self.connections) >= self.max_connections:
            self.log.warn('reached maximum number of connections', max_connections=self.max_connections)
            protocol.disconnect(force=True)
            return
        self.connections.add(protocol)
        self.handshaking_peers.add(protocol)

        self.pubsub.publish(
            HathorEvents.NETWORK_PEER_CONNECTED,
            protocol=protocol,
            peers_count=self._get_peers_count()
        )

    def on_peer_ready(self, protocol: HathorProtocol) -> None:
        """Called when a peer is ready."""
        assert protocol.peer is not None
        protocol.peer = self.peer_storage.add_or_merge(protocol.peer)
        assert protocol.peer.id is not None

        self.handshaking_peers.remove(protocol)
        self.received_peer_storage.pop(protocol.peer.id, None)

        # we emit the event even if it's a duplicate peer as a matching
        # NETWORK_PEER_DISCONNECTED will be emmited regardless
        self.pubsub.publish(
            HathorEvents.NETWORK_PEER_READY,
            protocol=protocol,
            peers_count=self._get_peers_count()
        )

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

        if len(self.connected_peers) <= self.MAX_ENABLED_SYNC:
            protocol.enable_sync()

        if protocol.peer.id in self.always_enable_sync:
            protocol.enable_sync()

        # Notify other peers about this new peer connection.
        for conn in self.iter_ready_connections():
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
        self.pubsub.publish(
            HathorEvents.NETWORK_PEER_DISCONNECTED,
            protocol=protocol,
            peers_count=self._get_peers_count()
        )

    def iter_all_connections(self) -> Iterable[HathorProtocol]:
        """Iterate over all connections."""
        for conn in self.connections:
            yield conn

    def iter_ready_connections(self) -> Iterable[HathorProtocol]:
        """Iterate over ready connections."""
        for conn in self.connected_peers.values():
            yield conn

    def iter_not_ready_endpoints(self) -> Iterable[str]:
        """Iterate over not-ready connections."""
        for connecting_peer in self.connecting_peers.values():
            yield connecting_peer.connection_string
        for protocol in self.handshaking_peers:
            if protocol.connection_string is not None:
                yield protocol.connection_string
            else:
                self.log.warn('handshaking protocol has empty connection string', protocol=protocol)

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
        peer = self.received_peer_storage.add_or_merge(peer)
        self.connect_to_if_not_connected(peer, int(self.reactor.seconds()))

    def reconnect_to_all(self) -> None:
        """ It is called by the `lc_reconnect` timer and tries to connect to all known
        peers.

        TODO(epnichols): Should we always connect to *all*? Should there be a max #?
        """
        # when we have no connected peers left, run the discovery process again
        assert self.manager is not None
        now = self.reactor.seconds()
        if now - self._last_discovery >= self.PEER_DISCOVERY_INTERVAL:
            self._last_discovery = now
            self.do_discovery()
        # We need to use list() here because the dict might change inside connect_to_if_not_connected
        # when the peer is disconnected and without entrypoint
        for peer in list(self.peer_storage.values()):
            self.connect_to_if_not_connected(peer, int(now))

    def update_whitelist(self) -> Deferred[None]:
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
        # Twisted Agent does not have a direct way to configure the HTTP client timeout
        # only a TCP connection timeout.
        # In this request we need a timeout that encompasses the connection and download time.
        # The callLater below is a manual client timeout that includes it and
        # will cancel the deferred in case it's called
        timeout_call = self.reactor.callLater(WHITELIST_REQUEST_TIMEOUT, d.cancel)
        d.addBoth(self._update_whitelist_timeout, timeout_call)
        d.addCallback(readBody)
        d.addErrback(self._update_whitelist_err)
        d.addCallback(self._update_whitelist_cb)
        return d

    def _update_whitelist_timeout(self, param: Union[Failure, Optional[bytes]],
                                  timeout_call: 'IDelayedCall') -> Union[Failure, Optional[bytes]]:
        """ This method is always called for both cb and errback in the update whitelist get request deferred.
            Because of that, the first parameter type will depend, will be a failure in case of errback
            or optional bytes in case of cb (see _update_whitelist_cb).

            We just need to cancel the timeout call later and return the first parameter,
            to continue the cb/errback sequence.
        """
        if timeout_call.active():
            timeout_call.cancel()
        return param

    def _update_whitelist_err(self, *args: Any, **kwargs: Any) -> None:
        self.log.error('update whitelist failed', args=args, kwargs=kwargs)

    def _update_whitelist_cb(self, body: Optional[bytes]) -> None:
        assert self.manager is not None
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
        current_whitelist = set(self.manager.peers_whitelist)
        peers_to_add = new_whitelist - current_whitelist
        if peers_to_add:
            self.log.info('add new peers to whitelist', peers=peers_to_add)
        peers_to_remove = current_whitelist - new_whitelist
        if peers_to_remove:
            self.log.info('remove peers peers from whitelist', peers=peers_to_remove)
        for peer_id in peers_to_add:
            self.manager.add_peer_to_whitelist(peer_id)
        for peer_id in peers_to_remove:
            self.manager.remove_peer_from_whitelist_and_disconnect(peer_id)

    def connect_to_if_not_connected(self, peer: PeerId, now: int) -> None:
        """ Attempts to connect if it is not connected to the peer.
        """
        if not peer.entrypoints:
            # It makes no sense to keep storing peers that have disconnected and have no entrypoints
            # We will never be able to connect to them anymore and they will only keep spending memory
            # and other resources when used in APIs, so we are removing them here
            if peer.id not in self.connected_peers:
                self.peer_storage.remove(peer)
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
            assert isinstance(protocol.wrappedProtocol, HathorProtocol)
            protocol.wrappedProtocol.on_outbound_connect(url_peer_id, connection_string)
        self.connecting_peers.pop(endpoint)

    def connect_to(self, description: str, peer: Optional[PeerId] = None, use_ssl: Optional[bool] = None) -> None:
        """ Attempt to connect to a peer, even if a connection already exists.
        Usually you should call `connect_to_if_not_connected`.

        If `use_ssl` is True, then the connection will be wraped by a TLS.
        """
        for connecting_peer in self.connecting_peers.values():
            if connecting_peer.connection_string == description:
                self.log.debug('skipping because we are already connecting to this endpoint', endpoint=description)
                return

        if use_ssl is None:
            use_ssl = self.use_ssl
        connection_string, peer_id = description_to_connection_string(description)
        # When using twisted endpoints we can't have // in the connection string
        endpoint_url = connection_string.replace('//', '')
        endpoint = endpoints.clientFromString(self.reactor, endpoint_url)

        if self.localhost_only:
            if ('127.0.0.1' not in endpoint_url) and ('localhost' not in endpoint_url):
                return

        factory: IProtocolFactory
        if use_ssl:
            certificate_options = self.my_peer.get_certificate_options()
            factory = TLSMemoryBIOFactory(certificate_options, True, self.client_factory)
        else:
            factory = self.client_factory

        if peer is not None:
            now = int(self.reactor.seconds())
            peer.increment_retry_attempt(now)

        deferred = endpoint.connect(factory)
        self.connecting_peers[endpoint] = _ConnectingPeer(connection_string, deferred)

        deferred.addCallback(self._connect_to_callback, peer, endpoint, connection_string, peer_id)
        deferred.addErrback(self.on_connection_failure, peer, endpoint)
        self.log.info('connect to ', endpoint=description, peer=str(peer))
        self.pubsub.publish(
            HathorEvents.NETWORK_PEER_CONNECTING,
            peer=peer,
            peers_count=self._get_peers_count()
        )

    def listen(self, description: str, use_ssl: Optional[bool] = None) -> IStreamServerEndpoint:
        """ Start to listen for new connection according to the description.

        If `ssl` is True, then the connection will be wraped by a TLS.

        :Example:

        `manager.listen(description='tcp:8000')`

        :param description: A description of the protocol and its parameters.
        :type description: str
        """
        endpoint = endpoints.serverFromString(self.reactor, description)

        if use_ssl is None:
            use_ssl = self.use_ssl

        factory: IProtocolFactory
        if use_ssl:
            certificate_options = self.my_peer.get_certificate_options()
            factory = TLSMemoryBIOFactory(certificate_options, False, self.server_factory)
        else:
            factory = self.server_factory

        factory = NetfilterFactory(self, factory)

        self.log.info('listen on', endpoint=description)
        endpoint.listen(factory)

        # XXX: endpoint: IStreamServerEndpoint does not intrinsically have a port, but in practice all concrete cases
        #      that we have will have a _port attribute
        port = getattr(endpoint, '_port', None)
        assert self.manager is not None
        if self.manager.hostname and port is not None:
            proto, _, _ = description.partition(':')
            address = '{}://{}:{}'.format(proto, self.manager.hostname, port)
            assert self.manager.my_peer is not None
            self.manager.my_peer.entrypoints.append(address)

        return endpoint

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

    def sync_update(self) -> None:
        """Update the subset of connections that running the sync algorithm."""
        try:
            self._sync_rotate_if_needed()
        except Exception:
            self.log.error('_sync_rotate_if_needed failed', exc_info=True)

    def set_always_enable_sync(self, values: list[str]) -> None:
        """Set a new list of peers to always enable sync. This operation completely replaces the previous list."""
        new: set[str] = set(values)

        old = self.always_enable_sync
        if new == old:
            return

        to_enable = new - old
        to_disable = old - new

        self.log.info('update always_enable_sync', new=new, to_enable=to_enable, to_disable=to_disable)

        for peer_id in new:
            if peer_id not in self.connected_peers:
                continue
            self.connected_peers[peer_id].enable_sync()

        for peer_id in to_disable:
            if peer_id not in self.connected_peers:
                continue
            self.connected_peers[peer_id].disable_sync()

        self.always_enable_sync = new

    def _calculate_sync_rotate(self) -> _SyncRotateInfo:
        """Calculate new sync rotation."""
        current_enabled: set[str] = set()
        for peer_id, conn in self.connected_peers.items():
            if conn.is_sync_enabled():
                current_enabled.add(peer_id)

        candidates = list(self.connected_peers.keys())
        self.rng.shuffle(candidates)
        selected_peers: set[str] = set(candidates[:self.MAX_ENABLED_SYNC])

        to_disable = current_enabled - selected_peers
        to_enable = selected_peers - current_enabled

        # Do not disable peers in the `always_enable_sync`.
        to_disable.difference_update(self.always_enable_sync)

        return _SyncRotateInfo(
            candidates=candidates,
            old=current_enabled,
            new=selected_peers,
            to_disable=to_disable,
            to_enable=to_enable,
        )

    def _sync_rotate_if_needed(self, *, force: bool = False) -> None:
        """Rotate peers who we are syncing from."""
        now = self.reactor.seconds()
        dt = now - self._last_sync_rotate
        if not force and dt < self.SYNC_UPDATE_INTERVAL:
            return
        self._last_sync_rotate = now

        info = self._calculate_sync_rotate()

        self.log.info(
            'sync rotate',
            candidates=len(info.candidates),
            old=info.old,
            new=info.new,
            to_enable=info.to_enable,
            to_disable=info.to_disable,
        )

        for peer_id in info.to_disable:
            self.connected_peers[peer_id].disable_sync()

        for peer_id in info.to_enable:
            self.connected_peers[peer_id].enable_sync()
