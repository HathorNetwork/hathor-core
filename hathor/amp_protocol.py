# encoding: utf-8

from twisted.internet.protocol import Factory
from twisted.internet import protocol
from twisted.protocols import amp

from hathor.transaction import Transaction, Block

import pickle


class GetTx(amp.Command):
    arguments = [(b'hash', amp.String())]
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
    response = [(b'ret', amp.Integer())]


class HathorAMP(amp.AMP):
    def __init__(self, node):
        self.node = node

    def connectionMade(self):
        self.node.remoteConnection = self

    def get_tx(self, hash_hex):
        tx = self.node.tx_storage.get_transaction_by_hash(hash_hex)
        return {'tx': tx.to_json()}
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
        self.node.on_new_tx(tx)
        return {'ret': 0}
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


class AMPConnector(protocol.ProcessProtocol):
    """
    A L{ProcessProtocol} subclass that can understand and speak AMP.
    """

    def __init__(self, proto, name):
        """
        @param proto: An instance or subclass of L{amp.AMP}
        @type proto: L{amp.AMP}

        @param name: optional name of the subprocess.
        @type name: int
        """
        #self.finished = defer.Deferred()
        self.amp = proto
        self.name = name

    def signalProcess(self, signalID):
        """
        Send the signal signalID to the child process

        @param signalID: The signal ID that you want to send to the
                        corresponding child
        @type signalID: C{str} or C{int}
        """
        return self.transport.signalProcess(signalID)

    def connectionMade(self):
        print("Subprocess %s started." % (self.name,))
        self.amp.makeConnection(self)

    # Transport
    disconnecting = False

    def write(self, data):
        self.transport.write(data)

    def loseConnection(self):
        self.transport.loseConnection()

    def getPeer(self):
        return ('subprocess',)

    def getHost(self):
        return ('no host',)

    def childDataReceived(self, childFD, data):
        self.amp.dataReceived(data)

    def errReceived(self, data):
        for line in data.strip().splitlines():
            print("FROM %s: %s" % (self.name, line))

    def processEnded(self, status):
        print("Process: %s ended" % (self.name,))
        self.amp.connectionLost(status)
        #if status.check(error.ProcessDone):
        #    self.finished.callback('')
        #    return
        #self.finished.errback(status)
