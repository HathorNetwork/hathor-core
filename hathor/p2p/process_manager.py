# encoding: utf-8

from hathor.p2p.peer_id import PeerId
from hathor.p2p.node_sync import NodeSyncLeftToRightManager
from hathor.p2p.manager import ConnectionsManager
from hathor.p2p.factory import HathorServerFactory, HathorClientFactory
from hathor.process_protocol import ProcessProtocolFactory
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.exception import HathorError

from collections import defaultdict, deque
from enum import Enum
from math import log
import time
import random
import pickle

#from hathor.test_protocol import TestLineReceiver, TestFactory
from twisted.internet.endpoints import ProcessEndpoint, StandardIOEndpoint
from twisted.internet import stdio
from twisted.internet.endpoints import UNIXClientEndpoint, connectProtocol
from hathor.amp_protocol import HathorAMPFactory, AMPConnector, HathorAMP, \
                                GetTx, SendTx, TxExists, GetTips, GetLatestTimestamp, OnNewTx
from twisted.internet import protocol
from os import environ
from twisted.internet.defer import inlineCallbacks


class ProcessManager(object):
    """ HathorManager manages the node with the help of other specialized classes.

    Its primary objective is to handle DAG-related matters, ensuring that the DAG is always valid and connected.
    """

    def __init__(self, reactor, peer_id=None, network=None, hostname=None,
                 pubsub=None, wallet=None, tx_storage=None, default_port=40403):
        """
        :param reactor: Twisted reactor which handles the mainloop and the events.
        :type reactor: :py:class:`twisted.internet.Reactor`

        :param peer_id: Id of this node. If not given, a new one is created.
        :type peer_id: :py:class:`hathor.p2p.peer_id.PeerId`

        :param network: Name of the network this node participates. Usually it is either testnet or mainnet.
        :type network: string

        :param hostname: The hostname of this node. It is used to generate its entrypoints.
        :type hostname: string

        :param pubsub: If not given, a new one is created.
        :type pubsub: :py:class:`hathor.pubsub.PubSubManager`

        :param tx_storage: If not given, a :py:class:`TransactionMemoryStorage` one is created.
        :type tx_storage: :py:class:`hathor.transaction.storage.transaction_storage.TransactionStorage`

        :param default_port: Network default port. It is used when only ip addresses are discovered.
        :type default_port: int
        """
        self.reactor = reactor

        # Hostname, used to be accessed by other peers.
        self.hostname = hostname

        # Remote address, which can be different from local address.
        self.remote_address = None

        self.my_peer = peer_id or PeerId()
        self.network = network or 'testnet'

        # XXX Should we use a singleton or a new PeerStorage? [msbrogli 2018-08-29]
        self.tx_storage = tx_storage or TransactionMemoryStorage()

        self.peer_discoveries = []

        self.server_factory = HathorServerFactory(self.network, self.my_peer, node=self)
        self.client_factory = HathorClientFactory(self.network, self.my_peer, node=self)
        self.connections = ConnectionsManager(self.reactor, self.my_peer, self.server_factory, self.client_factory)

        #self.node_sync_manager = NodeSyncLeftToRightManager(self)
        self.remoteProcess = None
        self.remoteConnection = None

    def start(self):
        """ A factory must be started only once. And it is usually automatically started.
        """
        self.connections.start()

        for peer_discovery in self.peer_discoveries:
            peer_discovery.discover_and_connect(self.connections.connect_to)


        #serverEndpoint = StandardIOEndpoint(self.reactor)
        #def myprint(p):
        #    logging.debug(type(p))
        #d = serverEndpoint.listen(AMPProtocolFactory(self))
        #d.addCallback(myprint)

        #stdio.StandardIO(AMPConnector(AMPProtocol(self)))

        endpoint = UNIXClientEndpoint(self.reactor, '/tmp/file.sock')
        #connected = endpoint.connect(AMPProtocolFactory(self))
        d = connectProtocol(endpoint, HathorAMP(self))
        def handleConn(p):
            self.remoteProcess = p
        d.addCallback(handleConn)

    def stop(self):
        self.connections.stop()

    def add_peer_discovery(self, peer_discovery):
        self.peer_discoveries.append(peer_discovery)

    def on_tips_received(self, tip_blocks, tip_transactions, conn=None):
        self.node_sync_manager.on_tips_received(tip_blocks, tip_transactions, conn)

    def listen(self, description, ssl=False):
        endpoint = self.connections.listen(description, ssl)

        if self.hostname:
            proto, _, _ = description.partition(':')
            address = '{}:{}:{}'.format(proto, self.hostname, endpoint._port)
            self.my_peer.entrypoints.append(address)

    @inlineCallbacks
    def transaction_exists_by_hash(self, hash_hex):
        ret = yield self.remoteConnection.callRemote(TxExists, hash_hex=hash_hex)
        return ret['ret']

    @inlineCallbacks
    def transaction_exists_by_hash_bytes(self, hash):
        ret = yield self.transaction_exists_by_hash(hash.hex())
        return ret

    @inlineCallbacks
    def get_tx_tips(self, timestamp):
        ret = yield self.remoteConnection.callRemote(GetTips, timestamp=timestamp, type='tx')
        return pickle.loads(ret['tips'])

    @inlineCallbacks
    def get_block_tips(self, timestamp):
        ret = yield self.remoteConnection.callRemote(GetTips, timestamp=timestamp, type='block')
        return pickle.loads(ret['tips'])

    @inlineCallbacks
    def get_latest_timestamp(self):
        ret = yield self.remoteConnection.callRemote(GetLatestTimestamp)
        print('getlatesttimestamp')
        return ret['timestamp']

    def on_new_tx(self, tx):
        tx_type = 'block' if tx.is_block else 'tx'
        self.remoteConnection.callRemote(OnNewTx, tx_type=tx_type, tx_bytes=bytes(tx))
