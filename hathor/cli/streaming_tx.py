import os
import random
import time

from typing import Tuple

from zope.interface import implementer
from twisted.internet import interfaces, reactor
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver

from hathor.cli.run_node import RunNode
from hathor.transaction.storage.traversal import BFSWalk


@implementer(interfaces.IPushProducer)
class Producer(object):
    """
    Send back the requested number of random integers to the client.
    """

    def __init__(self, proto, count):
        self._proto = proto
        self._goal = count
        self._produced = 0
        self._paused = False

        tx_storage = proto.tx_storage
        #root = list(tx_storage.get_all_genesis())[0]
        root = tx_storage.get_transaction(bytes.fromhex('0000000008bfd52ed4756fc2204d89f3dd3499b4df62113f6adc4949a9ba714c'))
        bfs_walk = BFSWalk(tx_storage, is_dag_funds=True, is_dag_verifications=True, is_left_to_right=True)
        self.tx_iter = bfs_walk.run(root)

    def pauseProducing(self):
        """
        When we've produced data too fast, pauseProducing() will be called
        (reentrantly from within resumeProducing's sendLine() method, most
        likely), so set a flag that causes production to pause temporarily.
        """
        self._paused = True
        print('Pausing connection from {}'.format(self._proto.transport.getPeer()))

    def resumeProducing(self):
        """
        Resume producing integers.

        This tells the push producer to (re-)add itself to the main loop and
        produce integers for its consumer until the requested number of integers
        were returned to the client.
        """
        self._paused = False

        while not self._paused and self._produced < self._goal:
            #next_int = random.randrange(0, 10000)
            #next_int = random.getrandbits(800)
            #line = "{}".format(next_int).encode("ascii")
            #line = os.urandom(500 // 2).hex().encode("ascii")
            try:
                tx = next(self.tx_iter)
            except StopIteration:
                self._proto.sendLine('Not enough tx'.encode('ascii'))
                self._produced = self._goal
                break
            line = bytes(tx).hex().encode('ascii')
            self._proto.sendLine(line)
            self._produced += 1

        if self._produced == self._goal:
            self._proto.transport.unregisterProducer()
            self._proto.transport.loseConnection()

    def stopProducing(self):
        """
        When a consumer has died, stop producing data for good.
        """
        self._produced = self._goal


class ServeRandom(LineReceiver):
    """
    Serve up random integers.
    """

    def __init__(self, tx_storage) -> None:
        self.tx_storage = tx_storage
        self._time = None

    def connectionMade(self):
        """
        Once the connection is made we ask the client how many random integers
        the producer should return.
        """
        print('Connection made from {}'.format(self.transport.getPeer()))
        self.sendLine(b'How many random integers do you want?')

    def lineReceived(self, line):
        """
        This checks how many random integers the client expects in return and
        tells the producer to start generating the data.
        """
        count = int(line.strip())
        print('Client requested {} random integers!'.format(count))
        producer = Producer(self, count)
        self._time = time.time()
        self.transport.registerProducer(producer, True)
        producer.resumeProducing()

    def connectionLost(self, reason):
        if self._time:
            dt = time.time() - self._time
        else:
            dt = -1
        print('Connection lost from {} (elapsed {} seconds)'.format(self.transport.getPeer(), dt))


class ServeRandomFactory(ServerFactory):
    protocol = ServeRandom

    def __init__(self, tx_storage):
        super().__init__()
        self.tx_storage = tx_storage

    def buildProtocol(self, addr: Tuple[str, int]) -> ServeRandom:
        return self.protocol(self.tx_storage)


class StreamingTx(RunNode):
    def start_manager(self) -> None:
        pass

    def run(self) -> None:
        print('!!')
        factory = ServeRandomFactory(self.tx_storage)
        reactor.listenTCP(1234, factory)
        reactor.run()

def main():
    StreamingTx().run()
