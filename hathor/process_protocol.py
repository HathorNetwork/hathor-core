# encoding: utf-8

from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import Factory

import logging
logging.basicConfig(filename='/tmp/example.log',level=logging.DEBUG)


class ProcessProtocolLineReceiver(LineReceiver):
    def __init__(self, node):
        self.node = node
        self.factory = None

    def connectionMade(self):
        print("Connection made with subprocess");
        self.factory.conn = self
        self.setLineMode()

    def connectionLost(self, reason):
        print("Connection lost to process:", reason);
        # TODO reconnect?

    def lineReceived(self, line):
        line = line.decode('utf-8')
        print("*** received message", line)
        logging.debug(line)
        self.node.handleProcessMessage(line)

    def send_message(self, line):
        print('send message', line)
        self.sendLine(line.encode('utf-8'))


class ProcessProtocolFactory(Factory):
    def __init__(self, node):
        """
        :type node: HathorManager or ConnectionsManager
        """
        super().__init__()
        self.conn = None
        self.node = node

    def buildProtocol(self, addr):
        p = ProcessProtocolLineReceiver(self.node)
        p.factory = self
        return p

    def send_message(self, msg):
        if self.conn:
            self.conn.send_message(msg)
        else:
            # TODO not connected
            print("ERROR: not connected to process")
