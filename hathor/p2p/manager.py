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

from collections import deque
from typing import TYPE_CHECKING, Any, Iterable, NamedTuple, Optional

from structlog import get_logger
from twisted.internet import endpoints
from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IListeningPort, IProtocol, IProtocolFactory, IStreamClientEndpoint
from twisted.internet.task import LoopingCall
from twisted.protocols.tls import TLSMemoryBIOFactory, TLSMemoryBIOProtocol
from twisted.python.failure import Failure
from twisted.web.client import Agent

from hathor.conf.settings import HathorSettings
from hathor.p2p.connection_slot import Slot
from hathor.p2p.netfilter.factory import NetfilterFactory
from hathor.p2p.peer import PrivatePeer, PublicPeer, UnverifiedPeer
from hathor.p2p.peer_discovery import PeerDiscovery
from hathor.p2p.peer_endpoint import PeerAddress, PeerEndpoint
from hathor.p2p.peer_id import PeerId
from hathor.p2p.peer_storage import VerifiedPeerStorage
from hathor.p2p.protocol import HathorProtocol
from hathor.p2p.rate_limiter import RateLimiter
from hathor.p2p.states.ready import ReadyState
from hathor.p2p.sync_factory import SyncAgentFactory
from hathor.p2p.sync_version import SyncVersion
from hathor.p2p.utils import parse_whitelist
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.reactor import ReactorProtocol as Reactor
from hathor.transaction import BaseTransaction
from hathor.util import Random

if TYPE_CHECKING:
    from hathor.manager import HathorManager

logger = get_logger()

# The timeout in seconds for the whitelist GET request
WHITELIST_REQUEST_TIMEOUT = 45


class _SyncRotateInfo(NamedTuple):
    candidates: list[PeerId]
    old: set[PeerId]
    new: set[PeerId]
    to_disable: set[PeerId]
    to_enable: set[PeerId]


class _ConnectingPeer(NamedTuple):
    entrypoint: PeerEndpoint
    endpoint_deferred: Deferred





class PeerConnectionsMetrics(NamedTuple):
    connecting_peers_count: int
    handshaking_peers_count: int
    connected_peers_count: int
    known_peers_count: int


class ConnectionsManager:
    """ It manages all peer-to-peer connections and events related to control messages.
    """

    class GlobalRateLimiter:
        SEND_TIPS = 'NodeSyncTimestamp.send_tips'

    manager: Optional['HathorManager']
    connections: set[HathorProtocol]
    connected_peers: dict[PeerId, HathorProtocol]
    new_connection_from_queue: deque[PeerId]
    connecting_peers: dict[IStreamClientEndpoint, _ConnectingPeer]
    handshaking_peers: set[HathorProtocol]
    whitelist_only: bool
    verified_peer_storage: VerifiedPeerStorage
    _sync_factories: dict[SyncVersion, SyncAgentFactory]
    _enabled_sync_versions: set[SyncVersion]

    rate_limiter: RateLimiter

    outgoing_slot: Slot
    incoming_slot: Slot
    bootstrap_slot: Slot
    check_entrypoints_slot: Slot

    def __init__(
        self,
        settings: HathorSettings,
        reactor: Reactor,
        my_peer: PrivatePeer,
        pubsub: PubSubManager,
        ssl: bool,
        rng: Random,
        whitelist_only: bool,
        enable_ipv6: bool,
        disable_ipv4: bool,
    ) -> None:
        self.log = logger.new()
        self._settings = settings
        self.rng = rng
        self.manager = None

        self.MAX_ENABLED_SYNC = settings.MAX_ENABLED_SYNC
        self.SYNC_UPDATE_INTERVAL = settings.SYNC_UPDATE_INTERVAL
        self.PEER_DISCOVERY_INTERVAL = settings.PEER_DISCOVERY_INTERVAL

        self.reactor = reactor
        self.my_peer = my_peer
        # List of address descriptions to listen for new connections (eg: [tcp:8000])
        self.listen_address_descriptions: list[str] = []

        # List of actual IP address instances to listen for new connections
        self._listen_addresses: list[IPv4Address | IPv6Address] = []

        # List of peer discovery methods.
        self.peer_discoveries: list[PeerDiscovery] = []

        # Options
        self.localhost_only = False

        # Factories.
        from hathor.p2p.factory import HathorClientFactory, HathorDiscoveredFactory, HathorServerFactory
        self.use_ssl = ssl
        self.server_factory = HathorServerFactory(
            self.my_peer, p2p_manager=self, use_ssl=self.use_ssl, settings=self._settings
        )
        self.client_factory = HathorClientFactory(
            self.my_peer, p2p_manager=self, use_ssl=self.use_ssl, settings=self._settings
        )
        self.discovered_factory = HathorDiscoveredFactory(
            self.my_peer, p2p_manager=self, use_ssl=self.use_ssl, settings=self._settings
        )

        # Global maximum number of connections.
        self.max_connections: int = self._settings.PEER_MAX_CONNECTIONS

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

        # List of connections by each slot

        max_outgoing: int = settings.P2P_PEER_MAX_OUTGOING_CONNECTIONS
        max_incoming: int = settings.P2P_PEER_MAX_INCOMING_CONNECTIONS
        max_discovered: int = settings.P2P_PEER_MAX_DISCOVERED_PEERS_CONNECTIONS
        max_check_ep: int = settings.P2P_PEER_MAX_CHECK_PEER_CONNECTIONS

        self.outgoing_slot = Slot(HathorProtocol.ConnectionType.OUTGOING, settings, max_outgoing)
        self.incoming_slot = Slot(HathorProtocol.ConnectionType.INCOMING, settings, max_incoming)
        self.bootstrap_slot = Slot(HathorProtocol.ConnectionType.DISCOVERED, settings, max_discovered)
        self.check_entrypoints_slot = Slot(HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS, settings, max_check_ep)

        # Queue of ready peer-id's used by connect_to_peer_from_connection_queue to choose the next peer to pull a
        # random new connection from
        self.new_connection_from_queue = deque()

        # List of known peers.
        self.verified_peer_storage = VerifiedPeerStorage(rng=self.rng, max_size=self._settings.MAX_VERIFIED_PEERS)

        # Maximum unseen time before removing a peer (seconds).
        self.max_peer_unseen_dt: float = 30 * 60   # 30-minutes

        # A timer to try to reconnect to the disconnect known peers.
        self.lc_reconnect = LoopingCall(self.reconnect_to_all)
        self.lc_reconnect.clock = self.reactor

        # A timer to update sync of all peers.
        self.lc_sync_update = LoopingCall(self.sync_update)
        self.lc_sync_update.clock = self.reactor
        self.lc_sync_update_interval: float = 5  # seconds

        # Peers that always have sync enabled.
        self.always_enable_sync: set[PeerId] = set()

        # Timestamp of the last time sync was updated.
        self._last_sync_rotate: float = 0.

        # Connect to new peers in a timed loop, instead of as soon as possible
        self.lc_connect = LoopingCall(self.connect_to_peer_from_connection_queue)
        self.lc_connect.clock = self.reactor
        self.lc_connect_interval = 0.2  # seconds

        # A timer to try to reconnect to the disconnect known peers.
        if self._settings.ENABLE_PEER_WHITELIST:
            self.wl_reconnect = LoopingCall(self.update_whitelist)
            self.wl_reconnect.clock = self.reactor

        # Pubsub object to publish events
        self.pubsub = pubsub

        # Parameter to explicitly enable whitelist-only mode, when False it will still check the whitelist for sync-v1
        self.whitelist_only = whitelist_only

        # Parameter to enable IPv6 connections
        self.enable_ipv6 = enable_ipv6

        # Parameter to disable IPv4 connections
        self.disable_ipv4 = disable_ipv4

        # Timestamp when the last discovery ran
        self._last_discovery: float = 0.

        # sync-manager factories
        self._sync_factories = {}
        self._enabled_sync_versions = set()

        # agent to perform HTTP requests
        self._http_agent = Agent(self.reactor)

    def add_sync_factory(self, sync_version: SyncVersion, sync_factory: SyncAgentFactory) -> None:
        """Add factory for the given sync version, must use a sync version that does not already exist."""
        # XXX: to allow code in `set_manager` to safely use the the available sync versions, we add this restriction:
        assert self.manager is None, 'Cannot modify sync factories after a manager is set'
        if sync_version in self._sync_factories:
            raise ValueError('sync version already exists')
        self._sync_factories[sync_version] = sync_factory

    def get_available_sync_versions(self) -> set[SyncVersion]:
        """What sync versions the manager is capable of using, they are not necessarily enabled."""
        return set(self._sync_factories.keys())

    def is_sync_version_available(self, sync_version: SyncVersion) -> bool:
        """Whether the given sync version is available for use, is not necessarily enabled."""
        return sync_version in self._sync_factories

    def get_enabled_sync_versions(self) -> set[SyncVersion]:
        """What sync versions are enabled for use, it is necessarily a subset of the available versions."""
        return self._enabled_sync_versions.copy()

    def is_sync_version_enabled(self, sync_version: SyncVersion) -> bool:
        """Whether the given sync version is enabled for use, being enabled implies being available."""
        return sync_version in self._enabled_sync_versions

    def enable_sync_version(self, sync_version: SyncVersion) -> None:
        """Enable using the given sync version on new connections, it must be available before being enabled."""
        assert sync_version in self._sync_factories
        if sync_version in self._enabled_sync_versions:
            self.log.info('tried to enable a sync verison that was already enabled, nothing to do')
            return
        self._enabled_sync_versions.add(sync_version)

    def disable_sync_version(self, sync_version: SyncVersion) -> None:
        """Disable using the given sync version, it WILL NOT close connections using the given version."""
        if sync_version not in self._enabled_sync_versions:
            self.log.info('tried to disable a sync verison that was already disabled, nothing to do')
            return
        self._enabled_sync_versions.discard(sync_version)

    def set_manager(self, manager: 'HathorManager') -> None:
        """Set the manager. This method must be called before start()."""
        if len(self._enabled_sync_versions) == 0:
            raise TypeError('Class built incorrectly without any enabled sync version')

        self.manager = manager

    def add_listen_address_description(self, addr: str) -> None:
        """Add address to listen for incoming connections."""
        self.listen_address_descriptions.append(addr)

    def add_peer_discovery(self, peer_discovery: PeerDiscovery) -> None:
        """Add a peer discovery method."""
        self.peer_discoveries.append(peer_discovery)

    def do_discovery(self) -> None:
        """
        Do a discovery and connect on all discovery strategies.
        """
        for peer_discovery in self.peer_discoveries:
            coro = peer_discovery.discover_and_connect(self.connect_to_endpoint)
            Deferred.fromCoroutine(coro)

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
        """Listen on the given address descriptions and start accepting and processing connections."""
        if self.manager is None:
            raise TypeError('Class was built incorrectly without a HathorManager.')

        self._start_peer_connect_loop()
        self.lc_reconnect.start(5, now=False)
        self.lc_sync_update.start(self.lc_sync_update_interval, now=False)

        if self._settings.ENABLE_PEER_WHITELIST:
            self._start_whitelist_reconnect()

        for description in self.listen_address_descriptions:
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

    def _start_peer_connect_loop(self) -> None:
        # The deferred returned by the LoopingCall start method
        # executes when the looping call stops running
        # https://docs.twistedmatrix.com/en/stable/api/twisted.internet.task.LoopingCall.html
        d = self.lc_connect.start(self.lc_connect_interval, now=True)
        d.addErrback(self._handle_peer_connect_err)

    def _handle_peer_connect_err(self, *args: Any, **kwargs: Any) -> None:
        # This method will be called when an exception happens inside the peer connect loop
        # and ends up stopping the looping call.
        # We log the error and start the looping call again.
        self.log.error(
            'connect_to_peer_from_connection_queue had an exception. Start looping call again.',
            args=args,
            kwargs=kwargs,
        )
        self.reactor.callLater(self.lc_connect_interval, self._start_peer_connect_loop)

    def stop(self) -> None:
        if self.lc_connect.running:
            self.lc_connect.stop()

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
            len(self.verified_peer_storage),
        )

    def get_sync_factory(self, sync_version: SyncVersion) -> SyncAgentFactory:
        """Get the sync factory for a given version, MUST be available or it will raise an assert."""
        assert sync_version in self._sync_factories, f'sync_version {sync_version} is not available'
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

    def on_connection_failure(self, failure: Failure, peer: Optional[UnverifiedPeer | PublicPeer],
                              endpoint: IStreamClientEndpoint) -> None:
        connecting_peer = self.connecting_peers[endpoint]
        entrypoint = connecting_peer.entrypoint
        self.log.warn('connection failure', entrypoint=str(entrypoint), failure=failure.getErrorMessage())
        self.connecting_peers.pop(endpoint)

        self.pubsub.publish(
            HathorEvents.NETWORK_PEER_CONNECTION_FAILED,
            peer=peer,
            peers_count=self._get_peers_count()
        )

    def on_peer_connect(self, protocol: HathorProtocol) -> None:
        """Called when a new connection is established."""

        # Checks whether connections in the network are at limit.
        if len(self.connections) >= self.max_connections:
            self.log.warn('reached maximum number of connections', max_connections=self.max_connections)
            protocol.disconnect(force=True)
            return

        connection_allowed = False  # If protocol is added to slot, True. If to Queue or disconnected, False.
        # Next block sends the connection to the appropriate slot.
        if protocol.connection_type == HathorProtocol.ConnectionType.OUTGOING:
            # Here, it can happend that the protocol changes to Check Entrypoints.
            connection_allowed = self.outgoing_slot.add_connection(protocol)
            # The check is done so discovered connections are not added doubly.

        if protocol.connection_type == HathorProtocol.ConnectionType.INCOMING:
            connection_allowed = self.incoming_slot.add_connection(protocol)

        if protocol.connection_type == HathorProtocol.ConnectionType.DISCOVERED:
            connection_allowed = self.bootstrap_slot.add_connection(protocol)

        if protocol.connection_type == HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS:
            connection_allowed = self.check_entrypoints_slot.add_connection(protocol)

        # Regardless of the slot sent, the total connections increases.
        # A connection waiting in queue is not added (yet) to the whole pool, only if another disconnects.
        if connection_allowed:
            self.connections.add(protocol)
            self.handshaking_peers.add(protocol)

            # If not queued, connection state is "CONNECTING", as it is not ready yet, added to handshaking.
            protocol.connection_state = HathorProtocol.ConnectionState.CONNECTING

            self.pubsub.publish(
                HathorEvents.NETWORK_PEER_CONNECTED,
                protocol=protocol,
                peers_count=self._get_peers_count()
            )

    def on_peer_ready(self, protocol: HathorProtocol) -> None:
        """Called when a peer is ready."""
        assert protocol.peer is not None
        self.verified_peer_storage.add_or_replace(protocol.peer)
        self.handshaking_peers.remove(protocol)

        for conn in self.iter_all_connections():
            conn.unverified_peer_storage.remove(protocol.peer)

        protocol.connection_state = HathorProtocol.ConnectionState.READY

        # we emit the event even if it's a duplicate peer as a matching
        # NETWORK_PEER_DISCONNECTED will be emitted regardless
        self.pubsub.publish(
            HathorEvents.NETWORK_PEER_READY,
            protocol=protocol,
            peers_count=self._get_peers_count()
        )

        peer_id = protocol.peer.id
        if peer_id in self.connected_peers:
            # connected twice to same peer
            self.log.warn('duplicate connection to peer', protocol=protocol)
            conn = self.get_connection_to_drop(protocol)
            self.reactor.callLater(0, self.drop_connection, conn)
            if conn == protocol:
                # the new connection is being dropped, so don't save it to connected_peers
                return

        self.connected_peers[peer_id] = protocol
        if peer_id not in self.new_connection_from_queue:
            self.new_connection_from_queue.append(peer_id)
        else:
            self.log.warn('peer already in queue', peer=str(peer_id))

        # In case it was a retry, we must reset the data only here, after it gets ready
        protocol.peer.info.reset_retry_timestamp()

        if len(self.connected_peers) <= self.MAX_ENABLED_SYNC:
            protocol.enable_sync()

        if peer_id in self.always_enable_sync:
            protocol.enable_sync()

        # Notify other peers about this new peer connection.
        self.relay_peer_to_ready_connections(protocol.peer)

        # If it is a connection for checking entrypoint only, we must disconnect now.
        if protocol.connection_type == HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS:
            protocol.disconnect(reason="READY connection for check_entrypoint slot.")

    def relay_peer_to_ready_connections(self, peer: PublicPeer) -> None:
        """Relay peer to all ready connections."""
        for conn in self.iter_ready_connections():
            if conn.peer == peer:
                continue
            assert isinstance(conn.state, ReadyState)
            conn.state.send_peers([peer])

    def on_peer_disconnect(self, protocol: HathorProtocol) -> None:
        """Called when a peer disconnect."""

        # Discard handles case when not in connections.
        self.connections.discard(protocol)

        # If the protocol discarded is from check_entrypoints slot.
        dequeued_ep = None

        # Each conn is from a slot - discard from it as well.
        if protocol.connection_type == HathorProtocol.ConnectionType.OUTGOING:
            self.outgoing_slot.remove_connection(protocol)

        if protocol.connection_type == HathorProtocol.ConnectionType.INCOMING:
            self.incoming_slot.remove_connection(protocol)

        if protocol.connection_type == HathorProtocol.ConnectionType.DISCOVERED:
            self.bootstrap_slot.remove_connection(protocol)

        # The only connection type that may pop from a queue is CHECK_ENTRYPOINTS
        if protocol.connection_type == HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS:
            dequeued_ep = self.check_entrypoints_slot.remove_connection(protocol)
            # For a given ep, check if some verified peer has it. If so, pop it off and restart.
            while dequeued_ep:
                for peer in self.verified_peer_storage.values():
                    if dequeued_ep in peer.info.entrypoints:
                        dequeued_ep = self.check_entrypoints_slot.remove_connection(protocol, True, dequeued_ep)
                        break
                if dequeued_ep and dequeued_ep not in peer.info.entrypoints:
                    self.connect_to_endpoint(entrypoint=dequeued_ep.with_id(None))

        if protocol in self.handshaking_peers:
            self.handshaking_peers.remove(protocol)

        if protocol._peer is not None:
            peer_id = protocol.peer.id
            existing_protocol = self.connected_peers.pop(peer_id, None)
            if existing_protocol is None:
                # in this case, the connection was closed before it got to READY state
                return
            if existing_protocol != protocol:
                # this is the case we're closing a duplicate connection. We need to set the
                # existing protocol object back to connected_peers, as that connection is still ongoing.
                # A check for duplicate connections is done during PEER_ID state, but there's still a
                # chance it can happen if both connections start at the same time and none of them has
                # reached READY state while the other is on PEER_ID state
                self.connected_peers[peer_id] = existing_protocol
            elif peer_id in self.new_connection_from_queue:
                # now we're sure it can be removed from new_connection_from_queue
                self.new_connection_from_queue.remove(peer_id)

        self.pubsub.publish(
            HathorEvents.NETWORK_PEER_DISCONNECTED,
            protocol=protocol,
            peers_count=self._get_peers_count()
        )

        # SUGGESTION: To make a NETWORK_PEER_DEQUEUED. It would be clearer, since in the case of a dequeue,
        # the order of events would be "NETWORK_PEER_READY" and then "NETWORK_PEER_CONNECTED", which is
        # the opposite.

    def iter_all_connections(self) -> Iterable[HathorProtocol]:
        """Iterate over all connections."""
        yield from self.connections

    def iter_ready_connections(self) -> Iterable[HathorProtocol]:
        """Iterate over ready connections."""
        yield from self.connected_peers.values()

    def iter_not_ready_endpoints(self) -> Iterable[PeerEndpoint]:
        """Iterate over not-ready connections."""
        for connecting_peer in self.connecting_peers.values():
            yield connecting_peer.entrypoint
        for protocol in self.handshaking_peers:
            if protocol.entrypoint is not None:
                yield protocol.entrypoint
            else:
                self.log.warn('handshaking protocol has empty connection string', protocol=protocol)

    def is_peer_connected(self, peer_id: PeerId) -> bool:
        """
        :type peer_id: string (peer.id)
        """
        return peer_id in self.connected_peers

    def peers_cleanup(self) -> None:
        """Clean up aged peers."""
        now = self.reactor.seconds()
        to_be_removed: list[PublicPeer] = []
        for peer in self.verified_peer_storage.values():
            assert peer.id is not None
            if self.is_peer_connected(peer.id):
                continue
            dt = now - peer.info.last_seen
            if dt > self.max_peer_unseen_dt:
                to_be_removed.append(peer)

        for remove_peer in to_be_removed:
            self.verified_peer_storage.remove(remove_peer)

    def connect_to_peer_from_connection_queue(self) -> None:
        """ It is called by the `lc_connect` looping call and tries to connect to a new peer.
        """
        if not self.new_connection_from_queue:
            return
        assert self.manager is not None
        self.log.debug('connect to peer from connection queue')
        candidate_new_peers: list[UnverifiedPeer]
        # we don't know if we will find a candidate, so we can't do `while True:`
        for _ in range(len(self.new_connection_from_queue)):
            # for a deque([1, 2, 3, 4]) this will get 1 and modify it to deque([2, 3, 4, 1])
            next_from_peer_id = self.new_connection_from_queue[0]
            self.new_connection_from_queue.rotate(-1)

            protocol = self.connected_peers.get(next_from_peer_id)
            if protocol is None:
                self.log.error('expected protocol not found', peer_id=str(next_from_peer_id))
                assert self.new_connection_from_queue.pop() == next_from_peer_id
                continue
            candidate_new_peers = [
                candidate_peer
                for candidate_peer_id, candidate_peer in protocol.unverified_peer_storage.items()
                if candidate_peer_id not in self.connected_peers or candidate_peer_id not in self.connecting_peers
            ]
            if candidate_new_peers:
                break
        else:
            self.log.debug('no new peers in the connection queue')
            # this means we rotated through the whole queue and did not find any candidate
            return

        peer = self.rng.choice(candidate_new_peers)
        self.log.debug('random peer chosen', peer=str(peer.id), entrypoints=peer.info.entrypoints_as_str())
        now = self.reactor.seconds()
        self.connect_to_peer(peer, int(now))

    def reconnect_to_all(self) -> None:
        """ It is called by the `lc_reconnect` timer and tries to connect to all known peers.
        """
        self.peers_cleanup()
        # when we have no connected peers left, run the discovery process again
        assert self.manager is not None
        now = self.reactor.seconds()
        if now - self._last_discovery >= self.PEER_DISCOVERY_INTERVAL:
            self._last_discovery = now
            self.do_discovery()
        # We need to use list() here because the dict might change inside connect_to_peer
        # when the peer is disconnected and without entrypoint
        for peer in list(self.verified_peer_storage.values()):
            self.connect_to_peer(peer, int(now))

    def update_whitelist(self) -> Deferred[None]:
        from twisted.web.client import readBody
        from twisted.web.http_headers import Headers
        assert self._settings.WHITELIST_URL is not None
        self.log.info('update whitelist')
        d = self._http_agent.request(
            b'GET',
            self._settings.WHITELIST_URL.encode(),
            Headers({'User-Agent': ['hathor-core']}),
            None)
        d.addCallback(readBody)
        d.addTimeout(WHITELIST_REQUEST_TIMEOUT, self.reactor)
        d.addCallback(self._update_whitelist_cb)
        d.addErrback(self._update_whitelist_err)

        return d

    def _update_whitelist_err(self, *args: Any, **kwargs: Any) -> None:
        self.log.error('update whitelist failed', args=args, kwargs=kwargs)

    def _update_whitelist_cb(self, body: bytes) -> None:
        assert self.manager is not None
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

    def connect_to_peer(self, peer: UnverifiedPeer | PublicPeer, now: int) -> None:
        """ Attempts to connect if it is not connected to the peer.
        """
        if not peer.info.entrypoints or (
            not self.enable_ipv6 and not peer.info.get_ipv4_only_entrypoints()
        ) or (
            self.disable_ipv4 and not peer.info.get_ipv6_only_entrypoints()
        ):
            # It makes no sense to keep storing peers that have disconnected and have no entrypoints
            # We will never be able to connect to them anymore and they will only keep spending memory
            # and other resources when used in APIs, so we are removing them here
            if peer.id not in self.connected_peers:
                self.verified_peer_storage.remove(peer)
            return
        if peer.id in self.connected_peers:
            return

        assert peer.id is not None
        if peer.info.can_retry(now):
            if self.enable_ipv6 and not self.disable_ipv4:
                addr = self.rng.choice(list(peer.info.entrypoints))
            elif self.enable_ipv6 and self.disable_ipv4:
                addr = self.rng.choice(peer.info.get_ipv6_only_entrypoints())
            elif not self.enable_ipv6 and not self.disable_ipv4:
                addr = self.rng.choice(peer.info.get_ipv4_only_entrypoints())
            else:
                raise ValueError('IPv4 is disabled and IPv6 is not enabled')
            self.connect_to_endpoint(addr.with_id(peer.id), peer)
        else:
            self.log.debug('connecting too often, skip retrying', peer=str(peer.id))

    def _connect_to_callback(
        self,
        protocol: IProtocol,
        peer: UnverifiedPeer | PublicPeer | None,
        endpoint: IStreamClientEndpoint,
        entrypoint: PeerEndpoint,
        discovery_call: bool = False
    ) -> None:
        """Called when we successfully connect to a peer."""
        if isinstance(protocol, HathorProtocol):
            if discovery_call:
                protocol.connection_type = HathorProtocol.ConnectionType.DISCOVERED
            protocol.on_outbound_connect(entrypoint, peer)
        else:
            assert isinstance(protocol, TLSMemoryBIOProtocol)
            assert isinstance(protocol.wrappedProtocol, HathorProtocol)
            if discovery_call:
                protocol.wrappedProtocol.connection_type = HathorProtocol.ConnectionType.DISCOVERED
            protocol.wrappedProtocol.on_outbound_connect(entrypoint, peer)
        self.connecting_peers.pop(endpoint)

    def connect_to_endpoint(
        self,
        entrypoint: PeerEndpoint,
        peer: UnverifiedPeer | PublicPeer | None = None,
        use_ssl: bool | None = None,
        discovery_call: bool = False
    ) -> None:
        """ Attempt to connect directly to an endpoint, prefer calling `connect_to_peer` when possible.

        This method does not take into account the peer's id (since we might not even know it, or have verified it even
        if we know). But this method will check if there's already a connection open to the given endpoint and skip it
        if there is one.

        If `use_ssl` is True, then the connection will be wraped by a TLS.
        """

        if entrypoint.peer_id is not None and peer is not None and entrypoint.peer_id != peer.id:
            self.log.debug('skipping because the entrypoint peer_id does not match the actual peer_id',
                           entrypoint=str(entrypoint))
            return

        for connecting_peer in self.connecting_peers.values():
            if connecting_peer.entrypoint.addr == entrypoint.addr:
                self.log.debug(
                    'skipping because we are already connecting to this endpoint',
                    entrypoint=str(entrypoint),
                )
                return

        if self.localhost_only and not entrypoint.addr.is_localhost():
            self.log.debug('skip because of simple localhost check', entrypoint=str(entrypoint))
            return

        if not self.enable_ipv6 and entrypoint.addr.is_ipv6():
            self.log.info('skip because IPv6 is disabled', entrypoint=entrypoint)
            return

        if self.disable_ipv4 and entrypoint.addr.is_ipv4():
            self.log.info('skip because IPv4 is disabled', entrypoint=entrypoint)
            return

        if use_ssl is None:
            use_ssl = self.use_ssl

        endpoint = entrypoint.addr.to_client_endpoint(self.reactor)

        factory: IProtocolFactory
        if discovery_call:
            if use_ssl:
                factory = TLSMemoryBIOFactory(self.my_peer.certificate_options, True, self.discovered_factory)
            else:
                factory = self.discovered_factory
        else:
            if use_ssl:
                factory = TLSMemoryBIOFactory(self.my_peer.certificate_options, True, self.client_factory)
            else:
                factory = self.client_factory

        if peer is not None:
            now = int(self.reactor.seconds())
            peer.info.increment_retry_attempt(now)

        deferred = endpoint.connect(factory)
        self.connecting_peers[endpoint] = _ConnectingPeer(entrypoint, deferred)

        deferred.addCallback(self._connect_to_callback, peer, endpoint, entrypoint, discovery_call)
        deferred.addErrback(self.on_connection_failure, peer, endpoint)
        self.log.info('connecting to', entrypoint=str(entrypoint), peer=str(peer))
        self.pubsub.publish(
            HathorEvents.NETWORK_PEER_CONNECTING,
            peer=peer,
            peers_count=self._get_peers_count()
        )

    def listen(self, description: str, use_ssl: Optional[bool] = None) -> None:
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
            factory = TLSMemoryBIOFactory(self.my_peer.certificate_options, False, self.server_factory)
        else:
            factory = self.server_factory

        factory = NetfilterFactory(self, factory)

        self.log.info('trying to listen on', endpoint=description)
        deferred: Deferred[IListeningPort] = endpoint.listen(factory)
        deferred.addCallback(self._on_listen_success, description)

    def _on_listen_success(self, listening_port: IListeningPort, description: str) -> None:
        """Callback to be called when listening to an endpoint succeeds."""
        self.log.info('success listening on', endpoint=description)
        address = listening_port.getHost()

        if not isinstance(address, (IPv4Address, IPv6Address)):
            self.log.error(f'unhandled address type for endpoint "{description}": {str(type(address))}')
            return

        self._listen_addresses.append(address)

        assert self.manager is not None
        if self.manager.hostname:
            self._add_hostname_entrypoint(self.manager.hostname, address)

    def update_hostname_entrypoints(self, *, old_hostname: str | None, new_hostname: str) -> None:
        """Add new hostname entrypoints according to the listen addresses, and remove any old entrypoint."""
        assert self.manager is not None
        for address in self._listen_addresses:
            if old_hostname is not None:
                old_entrypoint = PeerAddress.from_hostname_address(old_hostname, address)
                if old_entrypoint in self.my_peer.info.entrypoints:
                    self.my_peer.info.entrypoints.remove(old_entrypoint)
            self._add_hostname_entrypoint(new_hostname, address)

    def _add_hostname_entrypoint(self, hostname: str, address: IPv4Address | IPv6Address) -> None:
        hostname_entrypoint = PeerAddress.from_hostname_address(hostname, address)
        self.my_peer.info.entrypoints.add(hostname_entrypoint)

    def get_connection_to_drop(self, protocol: HathorProtocol) -> HathorProtocol:
        """ When there are duplicate connections, determine which one should be dropped.

        We keep the connection initiated by the peer with larger id. A simple (peer_id1 > peer_id2)
        on the peer id string is used for this comparison.
        """
        assert protocol.peer is not None
        assert protocol.peer.id is not None
        assert protocol.my_peer.id is not None
        other_connection = self.connected_peers[protocol.peer.id]
        _outbound_types = (
            HathorProtocol.ConnectionType.OUTGOING,
            HathorProtocol.ConnectionType.DISCOVERED,
            HathorProtocol.ConnectionType.CHECK_ENTRYPOINTS,
        )
        is_outbound = protocol.connection_type in _outbound_types
        if bytes(protocol.my_peer.id) > bytes(protocol.peer.id):
            # connection started by me is kept
            if is_outbound:
                # other connection is dropped
                return other_connection
            else:
                # this was started by peer, so drop it
                return protocol
        else:
            # connection started by peer is kept
            if is_outbound:
                return protocol
            else:
                return other_connection

    def drop_connection(self, protocol: HathorProtocol) -> None:
        """ Drop a connection
        """
        assert protocol.peer is not None
        self.log.debug('dropping connection', peer_id=protocol.peer.id, protocol=type(protocol).__name__)
        protocol.send_error_and_close_connection('Connection droped')

    def drop_connection_by_peer_id(self, peer_id: PeerId) -> None:
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

    def set_always_enable_sync(self, values: list[PeerId]) -> None:
        """Set a new list of peers to always enable sync. This operation completely replaces the previous list."""
        new: set[PeerId] = set(values)

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
        current_enabled: set[PeerId] = set()
        for peer_id, conn in self.connected_peers.items():
            if conn.is_sync_enabled():
                current_enabled.add(peer_id)

        candidates = list(self.connected_peers.keys())
        self.rng.shuffle(candidates)
        selected_peers: set[PeerId] = set(candidates[:self.MAX_ENABLED_SYNC])

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

    def reload_entrypoints_and_connections(self) -> None:
        """Kill all connections and reload entrypoints from the original peer config file."""
        self.log.warn('Killing all connections and resetting entrypoints...')
        self.disconnect_all_peers(force=True)
        self.my_peer.reload_entrypoints_from_source_file()
