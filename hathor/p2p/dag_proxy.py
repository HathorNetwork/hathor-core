# encoding: utf-8

from hathor.transaction.genesis import genesis_transactions
from hathor.transaction import Block, Transaction
from hathor.amp_protocol import HathorAMP, GetTx, TxExists, GetTips, GetLatestTimestamp, OnNewTx

from twisted.internet.endpoints import UNIXClientEndpoint, connectProtocol
from twisted.internet.defer import inlineCallbacks

import pickle


class DAGProxy:
    """ DAGProxy communicates with the process handling the DAG.
    """

    def __init__(self, reactor, unix_socket=None):
        """
        :param reactor: Twisted reactor which handles the mainloop and the events.
        :type reactor: :py:class:`twisted.internet.Reactor`

        :param unix_socket: path to the unix socket
        :type unix_socket: string
        """
        self.reactor = reactor
        self.connections = None

        self.remoteConnection = None
        self.unix_socket = unix_socket

        self.genesis_hashes = []

    def start(self):
        endpoint = UNIXClientEndpoint(self.reactor, self.unix_socket)
        d = connectProtocol(endpoint, HathorAMP(self))

        def handleConn(p):
            self.remoteConnection = p
        d.addCallback(handleConn)

        genesis = genesis_transactions(None)
        for g in genesis:
            self.genesis_hashes.append(g.hash)
        self.first_timestamp = min(x.timestamp for x in genesis_transactions(None))

    def stop(self):
        # self.connections.stop()
        pass

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
        return ret['timestamp']

    @inlineCallbacks
    def on_new_tx(self, tx):
        tx_type = 'block' if tx.is_block else 'tx'
        ret = self.remoteConnection.callRemote(OnNewTx, tx_type=tx_type, tx_bytes=bytes(tx))
        return ret['ret']

    @inlineCallbacks
    def get_transaction_by_hash(self, hash_hex):
        ret = yield self.remoteConnection.callRemote(GetTx, hash_hex=hash_hex)
        tx_type = ret['tx_type']
        if tx_type == 'block':
            tx = Block.create_from_struct(ret['tx_bytes'])
        else:
            tx = Transaction.create_from_struct(ret['tx_bytes'])
        return tx

    def is_genesis(self, hash):
        return hash in self.genesis_hashes
