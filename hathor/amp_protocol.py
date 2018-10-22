# encoding: utf-8

from twisted.internet.protocol import Factory
from twisted.protocols import amp

from hathor.transaction import Transaction, Block

import pickle


class GetTx(amp.Command):
    arguments = [(b'hash_hex', amp.Unicode())]
    response = [(b'tx_type', amp.Unicode()),
                (b'tx_bytes', amp.String())]


class SendTx(amp.Command):
    arguments = [(b'tx_type', amp.Unicode()),
                 (b'tx_bytes', amp.String())]
    response = [(b'ret', amp.Integer())]


class TxExists(amp.Command):
    arguments = [(b'hash_hex', amp.Unicode())]
    response = [(b'ret', amp.Boolean())]


class GetTips(amp.Command):
    arguments = [(b'timestamp', amp.Integer()),
                 (b'type', amp.Unicode())]
    response = [(b'tips', amp.String())]


class GetLatestTimestamp(amp.Command):
    arguments = []
    response = [(b'timestamp', amp.Integer())]


class OnNewTx(amp.Command):
    arguments = [(b'tx_type', amp.Unicode()),
                 (b'tx_bytes', amp.String())]
    response = [(b'ret', amp.Boolean())]


class HathorAMP(amp.AMP):
    def __init__(self, node):
        self.node = node

    def connectionMade(self):
        self.node.remoteConnection = self

    def get_tx(self, hash_hex):
        tx = self.node.tx_storage.get_transaction_by_hash(hash_hex)
        tx_type = 'block' if tx.is_block else 'tx'
        return {'tx_type': tx_type, 'tx_bytes': bytes(tx)}
    GetTx.responder(get_tx)

    def tx_exists(self, hash_hex):
        ret = self.node.tx_storage.transaction_exists_by_hash(hash_hex)
        return {'ret': ret}
    TxExists.responder(tx_exists)

    def send_tx(self, tx_type, tx_bytes):
        if tx_type == 'block':
            tx = Block.create_from_struct(tx_bytes)
        else:
            tx = Transaction.create_from_struct(tx_bytes)
        self.node.connections.send_tx_to_peers(tx)
        return {'ret': 0}
    SendTx.responder(send_tx)

    def get_tips(self, timestamp, type):
        if type == 'block':
            ret = self.node.tx_storage.get_block_tips(timestamp)
        else:
            ret = self.node.tx_storage.get_tx_tips(timestamp)
        data = pickle.dumps(ret)
        return {'tips': data}
    GetTips.responder(get_tips)

    def get_latest_timestamp(self):
        ts = self.node.tx_storage.latest_timestamp
        return {'timestamp': ts}
    GetLatestTimestamp.responder(get_latest_timestamp)

    def on_new_tx(self, tx_type, tx_bytes):
        if tx_type == 'block':
            tx = Block.create_from_struct(tx_bytes)
        else:
            tx = Transaction.create_from_struct(tx_bytes)
        tx.storage = self.node.tx_storage
        ret = self.node.on_new_tx(tx)
        return {'ret': ret}
    OnNewTx.responder(on_new_tx)


class HathorAMPFactory(Factory):
    def __init__(self, node):
        """
        :type node: HathorManager or ProcessManager
        """
        super().__init__()
        self.node = node

    def buildProtocol(self, addr):
        return HathorAMP(self.node)
