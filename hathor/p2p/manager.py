"""
Copyright 2019 Hathor Labs

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from typing import TYPE_CHECKING, Dict, Optional, Set, Union

from structlog import get_logger
from twisted.internet import endpoints
from twisted.internet.base import ReactorBase
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IStreamClientEndpoint, IStreamServerEndpoint
from twisted.protocols.tls import TLSMemoryBIOFactory, TLSMemoryBIOProtocol
from twisted.python.failure import Failure

from hathor.p2p.downloader import Downloader
from hathor.p2p.peer_id import PeerId
from hathor.p2p.peer_storage import PeerStorage
from hathor.p2p.protocol import HathorProtocol
from hathor.p2p.states.ready import ReadyState
from hathor.p2p.utils import description_to_connection_string
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401
    from hathor.p2p.factory import HathorClientFactory, HathorServerFactory  # noqa: F401
    from hathor.p2p.node_sync import NodeSyncTimestamp  # noqa: F401

logger = get_logger()


class ConnectionsManager:
    """ It manages all peer-to-peer connections and events related to control messages.
    """

    connected_peers: Dict[str, HathorProtocol]
    connecting_peers: Dict[IStreamClientEndpoint, Deferred]
    handshaking_peers: Set[HathorProtocol]

    def __init__(self, reactor: ReactorBase, my_peer: PeerId, server_factory: 'HathorServerFactory',
                 client_factory: 'HathorClientFactory', pubsub: PubSubManager, manager: 'HathorManager',
                 ssl: bool) -> None:
        from twisted.internet.task import LoopingCall
        self.log = logger.new()

        self.reactor = reactor
        self.my_peer = my_peer

        # Factories.
        self.server_factory = server_factory
        self.server_factory.connections = self

        self.client_factory = client_factory
        self.client_factory.connections = self

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

        # Pubsub object to publish events
        self.pubsub = pubsub

        self.ssl = ssl

    def start(self) -> None:
        self.lc_reconnect.start(5)

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
        import random

        connections = list(self.get_ready_connections())
        random.shuffle(connections)
        for conn in connections:
            assert conn.state is not None
            assert isinstance(conn.state, ReadyState)
            conn.state.send_tx_to_peer(tx)

    def on_connection_failure(self, failure: Failure, peer: Optional[PeerId], endpoint: IStreamClientEndpoint) -> None:
        self.log.warn('connection failure', endpoint=endpoint, failure=failure.getErrorMessage())
        self.connecting_peers.pop(endpoint)
        if peer is not None:
            now = int(self.reactor.seconds())
            peer.update_retry_timestamp(now)

    def on_peer_connect(self, protocol: HathorProtocol) -> None:
        self.log.debug('peer connect', protocol=type(protocol).__name__)
        self.handshaking_peers.add(protocol)

    def on_peer_ready(self, protocol: HathorProtocol) -> None:
        assert protocol.peer is not None
        assert protocol.peer.id is not None

        self.log.debug('ready', peer_id=protocol.peer.id)
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
            self.reactor.callLater(0, self.drop_duplicate_connection, conn)
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
        self.log.debug('peer disconnect', protocol=type(protocol).__name__)
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

        TODO(epnichols): Should we always conect to *all*? Should there be a max #?
        """
        now = int(self.reactor.seconds())
        for peer in self.peer_storage.values():
            self.connect_to_if_not_connected(peer, now)

    def connect_to_if_not_connected(self, peer: PeerId, now: int) -> None:
        """ Attempts to connect if it is not connected to the peer.
        """
        import random

        if not peer.entrypoints:
            return
        if peer.id in self.connected_peers:
            return

        assert peer.id is not None
        if peer.can_retry(now):
            self.connect_to(random.choice(peer.entrypoints), peer)

    def _connect_to_callback(self, protocol: Union[HathorProtocol, TLSMemoryBIOProtocol], peer: Optional[PeerId],
                             endpoint: IStreamClientEndpoint, connection_string: str,
                             url_peer_id: Optional[str]) -> None:
        if isinstance(protocol, HathorProtocol):
            # Case it's not ssl
            conn_protocol = protocol
        else:
            conn_protocol = protocol.wrappedProtocol

        if url_peer_id:
            # Set in protocol the peer id extracted from the URL that must be validated
            conn_protocol.expected_peer_id = url_peer_id
        else:
            # Add warning flag
            conn_protocol.warning_flags.add(conn_protocol.WarningFlags.NO_PEER_ID_URL)

        # Setting connection string in protocol, so we can validate it matches the entrypoints data
        conn_protocol.connection_string = connection_string

        # this node started the connection
        conn_protocol.initiated_connection = True

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

    def listen(self, description: str, ssl: bool = True) -> IStreamServerEndpoint:
        """ Start to listen to new connection according to the description.

        If `ssl` is True, then the connection will be wraped by a TLS.

        :Example:

        `manager.listen(description='tcp:8000')`

        :param description: A description of the protocol and its parameters.
        :type description: str
        """
        endpoint = endpoints.serverFromString(self.reactor, description)

        if ssl:
            certificate_options = self.my_peer.get_certificate_options()
            factory = TLSMemoryBIOFactory(certificate_options, False, self.server_factory)
        else:
            factory = self.server_factory

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
            if protocol.initiated_connection:
                # other connection is dropped
                return other_connection
            else:
                # this was started by peer, so drop it
                return protocol
        else:
            # connection started by peer is kept
            if protocol.initiated_connection:
                return protocol
            else:
                return other_connection

    def drop_duplicate_connection(self, protocol: HathorProtocol) -> None:
        """ Drop a connection
        """
        assert protocol.peer is not None
        self.log.debug('dropping connection', peer_id=protocol.peer.id, protocol=type(protocol).__name__)
        protocol.send_error_and_close_connection('Connection already established')
