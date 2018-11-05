# encoding: utf-8

from twisted.protocols.basic import LineReceiver
from twisted.python import log
from twisted.logger import Logger
from autobahn.twisted.websocket import WebSocketServerProtocol
from autobahn.twisted.websocket import WebSocketClientProtocol

from hathor.p2p.states import HelloState, PeerIdState, ReadyState
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.rate_limiter import RateLimiter

from enum import Enum
import time


class HathorProtocol(object):
    """ Implements Hathor Peer-to-Peer Protocol. An instance of this class is
    created for each connection.

    When the connection is established, the protocol waits for a
    HELLO message, which will identify the application and give a
    nonce value.

    After receiving a HELLO message, the peer must reply with a PEER-ID
    message, which will identity the peer through its id, public key,
    and endpoints. There must be a signature of the nonce value which
    will be checked against the public key.

    After the PEER-ID message, the peer is ready to communicate.

    The available states are listed in PeerState class.
    The available commands are listed in the ProtocolMessages class.
    """
    log = Logger()

    class Metrics(object):
        def __init__(self):
            self.received_messages = 0
            self.sent_messages = 0
            self.received_bytes = 0
            self.sent_bytes = 0

    class RateLimitKeys(Enum):
        GLOBAL = 'global'

    class PeerState(Enum):
        HELLO = HelloState
        PEER_ID = PeerIdState
        READY = ReadyState

    def __init__(self, network, my_peer, connections=None, node=None):
        """
        :type network: string
        :type my_peer: PeerId
        :type connections: ConnectionsManager
        :type node: HathorManager
        """
        self.network = network
        self.my_peer = my_peer
        self.connections = connections
        self.node = node

        self._state_instances = {}

        self.app_version = 'Unknown'

        # The peer on the other side of the connection.
        self.peer = None

        # The last time a message has been received from this peer.
        self.last_message = 0
        self.metrics = self.Metrics()

        # The last time a request was send to this peer.
        self.last_request = 0

        # The time in which the connection was established.
        self.connection_time = 0

        # The current state of the connection.
        self.state = None

        # Default rate limit
        self.ratelimit = RateLimiter()
        # self.ratelimit.set_limit(self.RateLimitKeys.GLOBAL, 120, 60)

    def change_state(self, state_enum):
        if state_enum not in self._state_instances:
            state_cls = state_enum.value
            instance = state_cls(self)
            instance.state_name = state_enum.name
            self._state_instances[state_enum] = instance
        new_state = self._state_instances[state_enum]
        if new_state != self.state:
            if self.state:
                self.state.on_exit()
            self.state = new_state
            if self.state:
                self.state.on_enter()

    def on_connect(self):
        """ Executed when the connection is established.
        """
        remote = self.transport.getPeer()
        log.msg('HathorProtocol.connectionMade()', remote)

        self.connection_time = time.time()

        # The initial state is HELLO.
        self.change_state(self.PeerState.HELLO)

        if self.connections:
            self.connections.on_peer_connect(self)

    def on_disconnect(self, reason):
        """ Executed when the connection is lost.
        """
        remote = self.transport.getPeer()
        log.msg('HathorProtocol.connectionLost()', remote, reason)
        if self.state:
            self.state.on_exit()
        if self.connections:
            self.connections.on_peer_disconnect(self)

    def send_message(self, cmd, payload):
        """ A generic message which must be implemented to send a message
        to the peer. It depends on the underlying protocol in which
        HathorProtocol is running.
        """
        raise NotImplementedError

    def recv_message(self, cmd, payload):
        """ Executed when a new message arrives.
        """
        self.last_message = self.node.reactor.seconds()

        if not self.ratelimit.add_hit(self.RateLimitKeys.GLOBAL):
            self.state.send_throttle(self.RateLimitKeys.GLOBAL)
            return

        fn = self.state.cmd_map.get(cmd)
        if fn is not None:
            try:
                fn(payload)
            except Exception as e:
                self.log.warn('Unhandled Exception: {}'.format(e))
                raise
        else:
            self.send_error('Invalid Command: {}'.format(cmd))

    def send_error(self, msg):
        """ Send an error message to the peer.
        """
        self.send_message(ProtocolMessages.ERROR, msg)

    def send_error_and_close_connection(self, msg):
        """ Send an ERROR message to the peer, and then closes the connection.
        """
        self.send_error(msg)
        self.transport.loseConnection()

    def handle_error(self, payload):
        """ Executed when an ERROR command is received.
        """
        self.log.warn('ERROR {}'.format(payload))


class HathorLineReceiver(HathorProtocol, LineReceiver):
    """ Implements HathorProtocol in a LineReceiver protocol.
    It is simply a TCP connection which sends one message per line.
    """
    MAX_LENGTH = 65536

    def connectionMade(self):
        super(HathorLineReceiver, self).connectionMade()
        self.setLineMode()
        self.on_connect()

    def connectionLost(self, reason):
        super(HathorLineReceiver, self).connectionMade()
        self.on_disconnect(reason)

    def lineLengthExceeded(self, line):
        self.log.warn('lineLengthExceeded {} > {}: {}'.format(len(line), self.MAX_LENGTH, line))
        super(HathorLineReceiver, self).lineLengthExceeded(line)

    def lineReceived(self, line):
        self.metrics.received_messages += 1
        self.metrics.received_bytes += len(line)
        try:
            line = line.decode('utf-8')
        except UnicodeDecodeError:
            self.transport.loseConnection()
            return

        msgtype, _, msgdata = line.partition(' ')
        try:
            cmd = ProtocolMessages(msgtype)
        except ValueError:
            self.transport.loseConnection()
            return
        else:
            self.recv_message(cmd, msgdata)

    def send_message(self, cmd_enum, payload=None):
        cmd = cmd_enum.value
        if payload:
            line = '{} {}'.format(cmd, payload).encode('utf-8')
        else:
            line = cmd.encode('utf-8')
        self.metrics.sent_messages += 1
        self.metrics.sent_bytes += len(line)
        self.sendLine(line)


class HathorWebSocketServerProtocol(WebSocketServerProtocol, HathorProtocol):
    def onMessage(self, payload, isBinary):
        pass


class HathorWebSocketClientProtocol(WebSocketClientProtocol, HathorProtocol):
    def onMessage(self, payload, isBinary):
        pass
