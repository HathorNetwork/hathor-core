# encoding: utf-8

from twisted.protocols.basic import LineReceiver
from twisted.python import log
from autobahn.twisted.websocket import WebSocketServerProtocol
from autobahn.twisted.websocket import WebSocketClientProtocol

from hathor.p2p.states import HelloState, PeerIdState, ReadyState
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
    The available commands are listed in the ProtocolCommand class.
    """
    class RateLimitKeys(Enum):
        GLOBAL = 'global'

    class PeerState(Enum):
        HELLO = HelloState
        PEER_ID = PeerIdState
        READY = ReadyState

    def __init__(self, factory):
        self.factory = factory
        self.manager = self.factory.manager

        self._state_instances = {}

        # The peer on the other side of the connection.
        self.peer = None

        # It triggers an event to send a ping message if necessary.
        self.lc_ping = None

        # The last time a message has been received from this peer.
        self.last_message = 0

        # The last time a request was send to this peer.
        self.last_request = 0

        # The current state of the connection.
        self.state = None

        # Rate limit
        self.ratelimit = RateLimiter()
        self.ratelimit.set_limit(self.RateLimitKeys.GLOBAL, 120, 60)

    def change_state(self, state_enum):
        if state_enum not in self._state_instances:
            state_cls = state_enum.value
            self._state_instances[state_enum] = state_cls(self)
        new_state = self._state_instances[state_enum]
        if new_state != self.state:
            if self.state:
                self.state.on_exit()
            self.state = new_state
            if self.state:
                self.state.on_enter()

    def connectionMade(self):
        """ Executed when the connection is established.
        """
        remote = self.transport.getPeer()
        log.msg('HathorProtocol.connectionMade()', remote)

        # The initial state is HELLO.
        self.change_state(self.PeerState.HELLO)

    def connectionLost(self, reason):
        """ Executed when the connection is lost.
        """
        remote = self.transport.getPeer()
        log.msg('HathorProtocol.connectionLost()', remote)
        self.state.on_exit()
        self.state = None

    def send_message(self, cmd, payload):
        """ A generic message which must be implemented to send a message
        to the peer. It depends on the underlying protocol in which
        HathorProtocol is running.
        """
        raise NotImplemented()

    def recv_message(self, cmd, payload):
        """ Executed when a new message arrives.
        """
        self.last_message = time.time()

        if not self.ratelimit.add_hit(self.RateLimitKeys.GLOBAL):
            self.state.send_throttle(self.RateLimitKeys.GLOBAL)
            return

        fn = self.state.cmd_map.get(cmd)
        if fn is not None:
            try:
                fn(payload)
            except Exception as e:
                print('Unhandled Exception:', e)
                raise
        else:
            self.send_error(self.ProtocolCommand.ERROR, 'Invalid Command: {}'.format(cmd))

    def send_error(self, msg):
        """ Send an error message to the peer.
        """
        self.send_message(self.state.ProtocolCommand.ERROR, msg)

    def send_error_and_close_connection(self, msg):
        """ Send an ERROR message to the peer, and then closes the connection.
        """
        self.send_error(msg)
        self.transport.loseConnection()

    def handle_error(self, payload):
        """ Executed when an ERROR command is received.
        """
        print('ERROR', payload)


class HathorLineReceiver(HathorProtocol, LineReceiver):
    """ Implements HathorProtocol in a LineReceiver protocol.
    It is simply a TCP connection which sends one message per line.
    """
    def connectionMade(self):
        self.setLineMode()
        super(HathorLineReceiver, self).connectionMade()

    def lineReceived(self, line):
        line = line.decode('utf-8')
        msgtype, _, msgdata = line.partition(' ')

        try:
            cmd = self.state.ProtocolCommand(msgtype)
            self.recv_message(cmd, msgdata)
        except ValueError:
            self.transport.loseConnection()

    def send_message(self, cmd_enum, payload=None):
        cmd = cmd_enum.value
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
