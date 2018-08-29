# encoding: utf-8

from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import Protocol
from twisted.internet.task import LoopingCall
from twisted.python import log
from autobahn.asyncio.websocket import WebSocketServerProtocol
from autobahn.asyncio.websocket import WebSocketClientProtocol

from hathor.p2p.peer_id import PeerId
import hathor

from enum import Enum
import json
import time
import uuid
import base64


class HathorProtocol(Protocol):
    """ Implements Hathor Protocol.

    When the connection is established, the protocol waits for a
    HELLO message, which will identify the application and give a
    nonce value.

    After receiving a HELLO message, the peer must reply with a PEER-ID
    message, which will identity the peer through its id, public key,
    and endpoints. There must be a signature of the nonce value which
    will be checked against the public key.

    After the PEER-ID message, the peer is ready to communicate.

    The available states are listed in PeerState class.
    The available commands are listed in the ProtocolCommand class.
    """

    class PeerState(Enum):
        HELLO = 'HELLO'
        PEER_ID = 'PEER-ID'
        READY = 'READY'

    class ProtocolCommand(Enum):
        HELLO = 'HELLO'
        PEER_ID = 'PEER-ID'
        GET_PEERS = 'GET-PEERS'
        PEERS = 'PEERS'
        PING = 'PING'
        PONG = 'PONG'
        ERROR = 'ERROR'

    def __init__(self, factory):
        self.factory = factory
        self.peer_id = None
        self.lc_ping = None
        self.last_message = 0
        self.state = None

    def connectionMade(self):
        remote = self.transport.getPeer()
        # local = self.transport.getHost()
        self.state = self.PeerState.HELLO
        self.hello_nonce = str(uuid.uuid4())
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

        if cmd == self.ProtocolCommand.ERROR:
            self.handle_error(payload)
            return

        if self.state == self.PeerState.HELLO:
            if cmd == self.ProtocolCommand.HELLO:
                self.handle_hello(payload)
            else:
                self.send_error_and_close_connection('Only HELLO message is valid. Invalid command: {}'.format(cmd))
            return

        if self.state == self.PeerState.PEER_ID:
            if cmd == self.ProtocolCommand.PEER_ID:
                self.handle_peer_id(payload)
            else:
                self.send_error_and_close_connection('Only PEER-ID message is valid. Invalid command: {}'.format(cmd))
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

    def send_error(self, msg):
        print('Sending error message:', msg)
        self.send_message(self.ProtocolCommand.ERROR, msg)

    def send_error_and_close_connection(self, msg):
        self.send_error(msg)
        self.transport.loseConnection()

    def handle_error(self, payload):
        print('ERROR', payload)

    def send_get_peers(self):
        self.send_message(self.ProtocolCommand.GET_PEERS)

    def handle_get_peers(self, payload):
        print('handle_get_peers:')
        self.send_peers()

    def send_peers(self):
        peers = []
        for peer in self.factory.connected_peers.values():
            # TODO: uncomment when endpoints are filled in.
            # if not peer.peer_id.endpoints:
            #     continue
            # peers.append((peer.peer_id.id, peer.endpoints))
            peers.append((peer.peer_id.id, []))
        self.send_message(self.ProtocolCommand.PEERS, json.dumps(peers))
        print('Peers: %s' % str(peers))

    def handle_peers(self, payload):
        self.received_peers = json.loads(payload)
        self.factory.update_peers(self, self.received_peers)
        remote = self.transport.getPeer()
        print(remote, 'PEERS', payload)

    def send_hello(self):
        data = {
            'app': 'Hathor v{}'.format(hathor.__version__),
            'nonce': self.hello_nonce,
        }
        self.send_message(self.ProtocolCommand.HELLO, json.dumps(data))

    def handle_hello(self, payload):
        try:
            data = json.loads(payload)
        except ValueError:
            self.send_error_and_close_connection('Invalid payload.')
            return

        if {'app', 'nonce'} != set(data):
            self.send_error_and_close_connection('Invalid payload.')
            return

        app = 'Hathor v{}'.format(hathor.__version__)
        if data['app'] != app:
            print('WARNING Different app versions:', data['app'])

        nonce = data['nonce']
        self.state = self.PeerState.PEER_ID
        self.send_peer_id(nonce)

    def send_peer_id(self, nonce):
        peer_id = self.factory.peer_id
        hello = {
            'id': peer_id.id,
            'pubKey': peer_id.get_public_key(),
            'endpoints': [],
            'nonce': nonce,
            'signature': base64.b64encode(peer_id.sign(nonce.encode('ascii'))).decode('ascii'),
        }
        self.send_message(self.ProtocolCommand.PEER_ID, json.dumps(hello))

    def handle_peer_id(self, payload):
        remote = self.transport.getPeer()
        print(remote, 'HELLO', payload)
        data = json.loads(payload)

        if self.hello_nonce != data['nonce']:
            self.send_error_and_close_connection('Invalid nonce.')
            return

        peer_id = PeerId.create_from_json(data)
        peer_id.validate()

        signature = base64.b64decode(data['signature'])
        if not peer_id.verify_signature(signature, self.hello_nonce.encode('ascii')):
            self.send_error_and_close_connection('Invalid signature.')
            return

        self.state = self.PeerState.READY

        self.peer_id = peer_id
        self.factory.connected_peers[self.peer_id.id] = self
        print('factory.connected_peers:' + str(self.factory.connected_peers))

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
    def connectionMade(self):
        self.setLineMode()
        super(HathorLineReceiver, self).connectionMade()

    def lineReceived(self, line):
        line = line.decode('utf-8')
        msgtype, _, msgdata = line.partition(' ')

        try:
            cmd = self.ProtocolCommand(msgtype)
            self.recv_message(cmd, msgdata)
        except ValueError:
            self.transport.loseConnection()

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
