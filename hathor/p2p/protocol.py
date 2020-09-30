import time
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, Generator, Optional, Set

from autobahn.twisted.websocket import WebSocketClientProtocol, WebSocketServerProtocol
from structlog import get_logger
from twisted.internet.interfaces import ITransport
from twisted.protocols.basic import LineReceiver
from twisted.python.failure import Failure

from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.peer_id import PeerId
from hathor.p2p.rate_limiter import RateLimiter
from hathor.p2p.states import BaseState, HelloState, PeerIdState, ReadyState

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401
    from hathor.p2p.manager import ConnectionsManager  # noqa: F401

logger = get_logger()


class HathorProtocol:
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

    class PeerState(Enum):
        HELLO = HelloState
        PEER_ID = PeerIdState
        READY = ReadyState

    class Metrics:
        def __init__(self) -> None:
            self.received_messages: int = 0
            self.sent_messages: int = 0
            self.received_bytes: int = 0
            self.sent_bytes: int = 0
            self.received_txs: int = 0
            self.discarded_txs: int = 0
            self.received_blocks: int = 0
            self.discarded_blocks: int = 0

        def format_bytes(self, value: int) -> str:
            """ Format bytes in MB and kB.
            """
            if value > 1024*1024:
                return '{:11.2f} MB'.format(value / 1024 / 1024)
            elif value > 1024:
                return '{:11.2f} kB'.format(value / 1024)
            else:
                return '{} B'.format(value)

        def print_stats(self, prefix: str = '') -> None:
            """ Print a status of the metrics in stdout.
            """
            print('----')
            print('{}Received:       {:8d} messages  {}'.format(
                prefix,
                self.received_messages,
                self.format_bytes(self.received_bytes))
            )
            print('{}Sent:           {:8d} messages  {}'.format(
                prefix,
                self.sent_messages,
                self.format_bytes(self.sent_bytes))
            )
            print('{}Blocks:         {:8d} received  {:8d} discarded ({:2.0f}%)'.format(
                prefix,
                self.received_blocks,
                self.discarded_blocks,
                100.0 * self.discarded_blocks / (self.received_blocks + self.discarded_blocks)
            ))
            print('{}Transactions:   {:8d} received  {:8d} discarded ({:2.0f}%)'.format(
                prefix,
                self.received_txs,
                self.discarded_txs,
                100.0 * self.discarded_txs / (self.received_txs + self.discarded_txs)
            ))
            print('----')

    class RateLimitKeys(str, Enum):
        GLOBAL = 'global'

    class WarningFlags(str, Enum):
        NO_PEER_ID_URL = 'no_peer_id_url'
        NO_ENTRYPOINTS = 'no_entrypoints'

    network: str
    my_peer: PeerId
    connections: Optional['ConnectionsManager']
    node: 'HathorManager'
    app_version: str
    last_message: float
    peer: Optional[PeerId]
    transport: ITransport
    state: Optional[BaseState]
    connection_time: float
    _state_instances: Dict[PeerState, BaseState]
    connection_string: Optional[str]
    expected_peer_id: Optional[str]
    warning_flags: Set[str]
    connected: bool
    initiated_connection: bool

    def __init__(self, network: str, my_peer: PeerId, connections: Optional['ConnectionsManager'] = None, *,
                 node: 'HathorManager', use_ssl: bool) -> None:
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
        self.connection_time = 0.0

        # The current state of the connection.
        self.state: Optional[BaseState] = None

        # Default rate limit
        self.ratelimit = RateLimiter()
        # self.ratelimit.set_limit(self.RateLimitKeys.GLOBAL, 120, 60)

        # Connection string of the peer
        # Used to validate if entrypoints has this string
        self.connection_string: Optional[str] = None

        # Peer id sent in the connection url that is expected to connect (optional)
        self.expected_peer_id: Optional[str] = None

        # Set of warning flags that may be added during the connection process
        self.warning_flags: Set[str] = set()

        # If peer is connected
        self.connected = False

        self.use_ssl = use_ssl

        # Set to true if this node initiated the connection
        self.initiated_connection = False

        self.log = logger.new()

    def change_state(self, state_enum: PeerState) -> None:
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

    def on_connect(self) -> None:
        """ Executed when the connection is established.
        """
        remote = self.transport.getPeer()
        self.log.info('peer connected', remote=remote)

        self.connection_time = time.time()

        # The initial state is HELLO.
        self.change_state(self.PeerState.HELLO)

        self.connected = True

        if self.connections:
            self.connections.on_peer_connect(self)

    def on_disconnect(self, reason: Failure) -> None:
        """ Executed when the connection is lost.
        """
        remote = self.transport.getPeer()
        self.log.info('disconnected', remote=remote, reason=reason.getErrorMessage())
        self.connected = False
        if self.state:
            self.state.on_exit()
        if self.connections:
            self.connections.on_peer_disconnect(self)

    def send_message(self, cmd: ProtocolMessages, payload: Optional[str] = None) -> None:
        """ A generic message which must be implemented to send a message
        to the peer. It depends on the underlying protocol in which
        HathorProtocol is running.
        """
        raise NotImplementedError

    def recv_message(self, cmd: ProtocolMessages, payload: str) -> Optional[Generator[Any, Any, None]]:
        """ Executed when a new message arrives.
        """
        assert self.state is not None

        self.last_message = self.node.reactor.seconds()

        if not self.ratelimit.add_hit(self.RateLimitKeys.GLOBAL):
            self.state.send_throttle(self.RateLimitKeys.GLOBAL)
            return None

        fn = self.state.cmd_map.get(cmd)
        if fn is not None:
            try:
                return fn(payload)
            except Exception:
                self.log.warn('recv_message processing error', exc_info=True)
                raise
        else:
            self.send_error_and_close_connection('Invalid Command: {}'.format(cmd))

        return None

    def send_error(self, msg: str) -> None:
        """ Send an error message to the peer.
        """
        self.log.warn('protocol error', msg=msg)
        self.send_message(ProtocolMessages.ERROR, msg)

    def send_error_and_close_connection(self, msg: str) -> None:
        """ Send an ERROR message to the peer, and then closes the connection.
        """
        self.send_error(msg)
        self.log.warn('close connection due to previous error')
        # from twisted docs: "If a producer is being used with the transport, loseConnection will only close
        # the connection once the producer is unregistered." We call on_exit to make sure any producers (like
        # the one from node_sync) are unregistered
        if self.state:
            self.state.on_exit()
        self.transport.loseConnection()

    def handle_error(self, payload: str) -> None:
        """ Executed when an ERROR command is received.
        """
        self.log.warn('remote error', payload=payload)


class HathorLineReceiver(HathorProtocol, LineReceiver):
    """ Implements HathorProtocol in a LineReceiver protocol.
    It is simply a TCP connection which sends one message per line.
    """
    MAX_LENGTH = 65536

    def connectionMade(self) -> None:
        super(HathorLineReceiver, self).connectionMade()
        self.setLineMode()
        self.on_connect()

    def connectionLost(self, reason: Failure) -> None:
        super(HathorLineReceiver, self).connectionLost()
        self.on_disconnect(reason)

    def lineLengthExceeded(self, line: str) -> None:
        self.log.warn('lineLengthExceeded', line=line, line_len=len(line), max_line_len=self.MAX_LENGTH)
        super(HathorLineReceiver, self).lineLengthExceeded(line)

    def lineReceived(self, line: bytes) -> Optional[Generator[Any, Any, None]]:
        self.metrics.received_messages += 1
        self.metrics.received_bytes += len(line)

        try:
            sline = line.decode('utf-8')
        except UnicodeDecodeError:
            self.transport.loseConnection()
            return None

        msgtype, _, msgdata = sline.partition(' ')
        try:
            cmd = ProtocolMessages(msgtype)
        except ValueError:
            self.transport.loseConnection()
            return None
        else:
            self.recv_message(cmd, msgdata)
            return None

    def send_message(self, cmd_enum: ProtocolMessages, payload: Optional[str] = None) -> None:
        cmd = cmd_enum.value
        if payload:
            line = '{} {}'.format(cmd, payload).encode('utf-8')
        else:
            line = cmd.encode('utf-8')
        self.metrics.sent_messages += 1
        self.metrics.sent_bytes += len(line)
        self.sendLine(line)


class HathorWebSocketServerProtocol(WebSocketServerProtocol, HathorProtocol):  # pragma: no cover
    def onMessage(self, payload, isBinary):
        pass


class HathorWebSocketClientProtocol(WebSocketClientProtocol, HathorProtocol):  # pragma: no cover
    def onMessage(self, payload, isBinary):
        pass
