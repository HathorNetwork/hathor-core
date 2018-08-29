# encoding: utf-8

from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import Protocol
from twisted.internet.task import LoopingCall
from twisted.python import log
from autobahn.asyncio.websocket import WebSocketServerProtocol
from autobahn.asyncio.websocket import WebSocketClientProtocol

from hathor.p2p.peer_id import PeerId

from enum import Enum
import json
import time


class HathorProtocol(Protocol):
    """ Implements Hathor Protocol.

    When the connection is established, the protocol waits for a
    HELLO message, which will identify the peer through its id,
    public key, and endpoints.

    After the HELLO message, the peer is ready to communicate.

    The available states are listed in PeerState class.
    The available commands are listed in the ProtocolCommand class.
    """

    class PeerState(Enum):
        HELLO = 'HELLO'
        READY = 'READY'

    class ProtocolCommand(Enum):
        HELLO = 'HELLO'
        GET_PEERS = 'GET-PEERS'
        PEERS = 'PEERS'
        PING = 'PING'
        PONG = 'PONG'

    def __init__(self, factory):
        self.factory = factory
        self.peer_id = None
        self.lc_ping = None
        self.last_message = 0

    def connectionMade(self):
        remote = self.transport.getPeer()
        # local = self.transport.getHost()
        self.setLineMode()
        self.state = self.PeerState.HELLO
        self.send_hello()
        log.msg('HathorLineReceiver.connectionMade()', remote)

    def connectionLost(self, reason):
        remote = self.transport.getPeer()
        if self.peer_id:
            self.factory.connected_peers.pop(self.peer_id.id, None)
        if self.lc_ping:
            self.lc_ping.stop()
        print('Connection lost:', remote)

    def send_message(self, cmd, payload):
        raise NotImplemented()

    def recv_message(self, cmd, payload):
        self.last_message = time.time()

        if self.state == self.PeerState.HELLO:
            if cmd == self.ProtocolCommand.HELLO:
                self.handle_hello(payload)
            else:
                print('Only HELLO message is valid. Invalid command: {}'.format(cmd))
            return

        cmd_map = {
            self.ProtocolCommand.PING: self.handle_ping,
            self.ProtocolCommand.PONG: self.handle_pong,
            self.ProtocolCommand.GET_PEERS: self.handle_get_peers,
            self.ProtocolCommand.PEERS: self.handle_peers,
        }

        fn = cmd_map.get(cmd)
        if fn is not None:
            fn(payload)
        else:
            print('Command invalid.')

    def send_get_peers(self):
        self.send_message(self.ProtocolCommand.GET_PEERS)

    def handle_get_peers(self, payload):
        self.send_peers()

    def send_peers(self):
        peers = []
        for peer in self.factory.connected_peers.values():
            if not peer.peer_id.endpoints:
                continue
            peers.append((peer.peer_id.id, peer.endpoints))
        self.send_message(self.ProtocolCommand.PEERS, json.dumps(peers))

    def handle_peers(self, payload):
        self.received_peers = json.loads(payload)
        self.factory.update_peers(self, self.received_peers)
        remote = self.transport.getPeer()
        print(remote, 'PEERS', payload)

    def send_hello(self):
        peer_id = self.factory.peer_id
        hello = {
            'id': peer_id.id,
            'pubKey': peer_id.get_public_key(),
            'endpoints': [],
            # TODO 'signature': signature,
        }
        self.send_message(self.ProtocolCommand.HELLO, json.dumps(hello))

    def handle_hello(self, payload):
        remote = self.transport.getPeer()
        print(remote, 'HELLO', payload)

        data = json.loads(payload)
        self.peer_id = PeerId.create_from_json(data)
        self.factory.connected_peers[self.peer_id.id] = self

        self.state = self.PeerState.READY

        self.lc_ping = LoopingCall(self.send_ping_if_necessary)
        self.lc_ping.start(1)

        self.send_get_peers()

    def send_ping_if_necessary(self):
        dt = time.time() - self.last_message
        if dt > 3:
            self.send_ping()

    def send_ping(self):
        self.send_message(self.ProtocolCommand.PING)

    def send_pong(self):
        self.send_message(self.ProtocolCommand.PONG)

    def handle_ping(self, payload):
        self.send_pong()

    def handle_pong(self, payload):
        remote = self.transport.getPeer()
        print('Got pong from', remote)
        self.last_message = time.time()


class HathorLineReceiver(LineReceiver, HathorProtocol):
    def lineReceived(self, line):
        line = line.decode('utf-8')
        msgtype, _, msgdata = line.partition(' ')

        cmd = self.ProtocolCommand(msgtype)
        self.recv_message(cmd, msgdata)

    def send_message(self, cmd, payload=None):
        if isinstance(cmd, self.ProtocolCommand):
            cmd = cmd.value
        if payload:
            line = '{} {}'.format(cmd, payload).encode('utf-8')
        else:
            line = cmd.encode('utf-8')
        self.sendLine(line)


class HathorWebSocketServerProtocol(WebSocketServerProtocol, HathorProtocol):
    def onMessage(self, payload, isBinary):
        pass


class HathorWebSocketClientProtocol(WebSocketClientProtocol, HathorProtocol):
    def onMessage(self, payload, isBinary):
        pass
