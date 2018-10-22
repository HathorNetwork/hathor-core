# encoding: utf-8

import random

from twisted.internet import endpoints
from twisted.internet.task import LoopingCall

from hathor.crypto.util import generate_privkey_crt_pem
from hathor.p2p.peer_storage import PeerStorage
from hathor.pubsub import HathorEvents


class ConnectionsManager:
    """ It manages all peer-to-peer connections and events related to control messages.
    """
    def __init__(self, reactor, my_peer, hostname, server_factory, client_factory, pubsub):
        self.reactor = reactor
        self.my_peer = my_peer
        self.hostname = hostname

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

        # A timer to try to reconnect to the disconnect known peers.
        self.lc_reconnect = LoopingCall(self.reconnect_to_all)
        self.lc_reconnect.clock = self.reactor

        self.peer_discoveries = []

        # Pubsub object to publish events
        self.pubsub = pubsub

    def start(self):
        self.lc_reconnect.start(5)

        for peer_discovery in self.peer_discoveries:
            peer_discovery.discover_and_connect(self.connect_to)

    def stop(self):
        if self.lc_reconnect.running:
            self.lc_reconnect.stop()

    def add_peer_discovery(self, peer_discovery):
        self.peer_discoveries.append(peer_discovery)

    def send_tx_to_peers(self, tx):
        """ Send `tx` to all ready peers.

        The connections are shuffled to fairly propagate among peers.
        It seems to be a good approach for a small number of peers. We need to analyze
        the best approach when the number of peers increase.

        :param tx: BaseTransaction to be sent.
        :type tx: py:class:`hathor.transaction.BaseTransaction`
        """
        connections = list(self.get_ready_connections())
        random.shuffle(connections)
        for conn in connections:
            conn.state.send_tx_to_peer(tx)

    def on_connection_failure(self, failure, endpoint):
        print('Connection failure: address={}:{} message={}'.format(endpoint._host, endpoint._port, failure))
        self.connecting_peers.pop(endpoint)

    def on_peer_connect(self, protocol):
        print('on_peer_connect()', protocol)
        self.handshaking_peers.add(protocol)

    def on_peer_ready(self, protocol):
        print('on_peer_ready()', protocol)
        self.handshaking_peers.remove(protocol)
        self.received_peer_storage.pop(protocol.peer.id, None)

        self.peer_storage.add_or_merge(protocol.peer)
        self.connected_peers[protocol.peer.id] = protocol

        # Notify other peers about this new peer connection.
        for conn in self.get_ready_connections():
            if conn != protocol:
                conn.state.send_peers([protocol])

        self.pubsub.publish(HathorEvents.NETWORK_PEER_CONNECTED, protocol=protocol)

    def on_peer_disconnect(self, protocol):
        print('on_peer_disconnect()', protocol)
        if protocol.peer:
            self.connected_peers.pop(protocol.peer.id)
        if protocol in self.handshaking_peers:
            self.handshaking_peers.remove(protocol)

        self.pubsub.publish(HathorEvents.NETWORK_PEER_DISCONNECTED, protocol=protocol)

    def get_ready_connections(self):
        """
        :rtype: Iter[HathorProtocol]
        """
        return self.connected_peers.values()

    def is_peer_connected(self, peer_id):
        """
        :type peer_id: string (peer.id)
        """
        return peer_id in self.connected_peers

    def on_receive_peer(self, peer, origin=None):
        """ Update a peer information in our storage, and instantly attempt to connect
        to it if it is not connected yet.
        """
        if peer.id == self.my_peer.id:
            return
        self.received_peer_storage.add_or_merge(peer)
        self.connect_to_if_not_connected(peer)

    def reconnect_to_all(self):
        """ It is called by the `lc_reconnect` timer and tries to connect to all known
        peers.

        TODO(epnichols): Should we always conect to *all*? Should there be a max #?
        """
        for peer in self.peer_storage.values():
            self.connect_to_if_not_connected(peer)

    def connect_to_if_not_connected(self, peer):
        """ Attempts to connect if it is not connected to the peer.
        """
        if not peer.entrypoints:
            return
        if peer.id in self.connected_peers:
            return
        self.connect_to(random.choice(peer.entrypoints))

    def _connect_to_callback(self, protocol, endpoint):
        self.connecting_peers.pop(endpoint)

    def connect_to(self, description, ssl=False):
        """ Attempt to connect to a peer, even if a connection already exists.
        Usually you should call `connect_to_if_not_connected`.

        If `ssl` is True, then the connection will be wraped by a TLS.
        """
        endpoint = endpoints.clientFromString(self.reactor, description)

        if ssl:
            from twisted.internet import ssl
            from twisted.protocols.tls import TLSMemoryBIOFactory
            context = ssl.ClientContextFactory()
            factory = TLSMemoryBIOFactory(context, True, self.client_factory)
        else:
            factory = self.client_factory

        deferred = endpoint.connect(factory)
        self.connecting_peers[endpoint] = deferred

        deferred.addCallback(self._connect_to_callback, endpoint)
        deferred.addErrback(self.on_connection_failure, endpoint)
        print('Connecting to: {}...'.format(description))

    def listen(self, description, ssl=False):
        """ Start to listen to new connection according to the description.

        If `ssl` is True, then the connection will be wraped by a TLS.

        :Example:

        `manager.listen(description='tcp:8000')`

        :param description: A description of the protocol and its parameters.
        :type description: str
        """
        endpoint = endpoints.serverFromString(self.reactor, description)

        if ssl:
            # XXX Is it safe to generate a new certificate for each connection?
            #     What about CPU usage when many new connections arrive?
            from twisted.internet.ssl import PrivateCertificate
            from twisted.protocols.tls import TLSMemoryBIOFactory
            certificate = PrivateCertificate.loadPEM(generate_privkey_crt_pem())
            contextFactory = certificate.options()
            factory = TLSMemoryBIOFactory(contextFactory, False, self.server_factory)

            # from twisted.internet.ssl import CertificateOptions, TLSVersion
            # options = dict(privateKey=certificate.privateKey.original, certificate=certificate.original)
            # contextFactory = CertificateOptions(
            #     insecurelyLowerMinimumTo=TLSVersion.TLSv1_2,
            #     lowerMaximumSecurityTo=TLSVersion.TLSv1_3,
            #     **options,
            # )
        else:
            factory = self.server_factory

        endpoint.listen(factory)
        print('Listening to: {}...'.format(description))

        if self.hostname:
            proto, _, _ = description.partition(':')
            address = '{}:{}:{}'.format(proto, self.hostname, endpoint._port)
            self.my_peer.entrypoints.append(address)

        return endpoint
